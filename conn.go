package datagrams

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	i2cp "github.com/go-i2p/go-i2cp"
)

// I2CPSession is an interface that abstracts the I2CP session operations needed
// by DatagramConn. This allows for testing without requiring a real I2P router.
//
// The interface includes only the methods DatagramConn actually uses, following
// the Interface Segregation Principle. This makes testing easier and documents
// the actual dependencies.
type I2CPSession interface {
	// Destination returns the I2P destination for this session.
	Destination() *i2cp.Destination

	// IsClosed returns true if the session has been closed.
	IsClosed() bool

	// IsOffline returns true if this session uses offline keys (LS2).
	// Sessions with offline keys should use Datagram2 instead of Datagram1.
	// Per I2P specification, Datagram1 does NOT support offline signatures.
	IsOffline() bool

	// SendMessage sends a datagram message to the specified destination.
	// This will be used by the SendTo implementation.
	SendMessage(destination *i2cp.Destination, protocol uint8, srcPort, destPort uint16, payload *i2cp.Stream, nonce uint32) error

	// SendMessageWithContext sends a message with context for cancellation.
	SendMessageWithContext(ctx context.Context, destination *i2cp.Destination, protocol uint8, srcPort, destPort uint16, payload *i2cp.Stream, nonce uint32) error

	// SigningKeyPair returns the Ed25519 signing key pair for this session.
	// This is used to sign authenticated datagrams (Datagram1, Datagram2).
	// Returns error if no signing key pair is available.
	SigningKeyPair() (*i2cp.Ed25519KeyPair, error)
}

// Verify that *i2cp.Session implements I2CPSession at compile time.
var _ I2CPSession = (*i2cp.Session)(nil)

// Verify that *DatagramConn implements net.PacketConn at compile time.
var _ net.PacketConn = (*DatagramConn)(nil)

// Protocol numbers for I2P datagram types.
// These are aliases to the constants defined in go-i2cp for convenience.
// See SPEC.md for detailed format specifications.
const (
	// ProtocolStreaming (6) is reserved for I2P streaming protocol.
	// This protocol number MUST NOT be used for datagrams.
	ProtocolStreaming = i2cp.ProtoStreaming

	// ProtocolRaw (18) is for non-repliable, non-authenticated datagrams.
	// Zero overhead, highest performance. Use for trusted peers or when
	// authentication is handled at the application layer.
	ProtocolRaw = i2cp.ProtoDatagramRaw

	// ProtocolDatagram1 (17) is for repliable, authenticated datagrams (legacy).
	// ~455 bytes overhead (Ed25519). Use for compatibility with older I2P applications.
	// WARNING: Does NOT support offline signatures (LS2 offline keys).
	ProtocolDatagram1 = i2cp.ProtoDatagram

	// ProtocolDatagram2 (19) is for repliable, authenticated datagrams with replay prevention.
	// ~457+ bytes overhead (Ed25519). Use for modern authenticated messaging requiring
	// protection against replay attacks. Supports offline signatures.
	ProtocolDatagram2 = i2cp.ProtoDatagram2

	// ProtocolDatagram3 (20) is for repliable, non-authenticated datagrams.
	// ~34 bytes overhead. Use when repliability is needed with minimal overhead
	// and authentication is not required.
	ProtocolDatagram3 = i2cp.ProtoDatagram3
)

// Size constants for I2P datagrams.
const (
	// MaxI2NPSize is the nominal maximum size for I2NP messages including datagrams.
	// Per I2P specification, this is 64KB but actual limits may be slightly less
	// due to I2CP gzip header (~10 bytes) and garlic message overhead.
	MaxI2NPSize = 64 * 1024 // 64 KB

	// RecommendedMaxSize is the recommended maximum payload size for reliable delivery.
	// I2NP messages fragment into 1KB tunnel messages, and drop probability increases
	// exponentially with size. This limit ensures good reliability.
	RecommendedMaxSize = 10 * 1024 // 10 KB

	// OptimalMaxSize is the optimal payload size for best reliability.
	// Keeping messages small reduces fragmentation and improves delivery probability.
	OptimalMaxSize = 4 * 1024 // 4 KB

	// Ed25519SignatureLength is the fixed signature length for Ed25519 (64 bytes).
	// go-i2cp exclusively uses Ed25519, so this is constant.
	Ed25519SignatureLength = 64

	// Ed25519DestinationSize is the wire format size for an Ed25519 destination.
	// Wire format: pubKey(256) + signingPubKey(128) + certificate(7) = 391 bytes
	//
	// Note: The I2P spec says "387+" for serialized format because DSA-SHA1 destinations
	// fit in 387 bytes. Ed25519 with KEY certificates requires 391 bytes due to the
	// certificate structure. This value is constant for go-i2cp's Ed25519-only destinations.
	Ed25519DestinationSize = 391

	// MinDatagram1Overhead is the minimum envelope overhead for Datagram1 with Ed25519.
	// destination(391) + signature(64) = 455 bytes
	//
	// This is the minimum because the destination size can vary with certificate type.
	// For go-i2cp's Ed25519-only destinations, this is also the exact overhead.
	MinDatagram1Overhead = Ed25519DestinationSize + Ed25519SignatureLength // 455

	// MinDatagram2Overhead is the minimum envelope overhead for Datagram2 with Ed25519.
	// destination(391) + flags(2) + signature(64) = 457 bytes (without options or offline sig)
	//
	// Actual overhead may be larger when:
	// - Options field is present (adds 2+ bytes for mapping)
	// - Offline signature is present (adds ~102 bytes for Ed25519)
	MinDatagram2Overhead = Ed25519DestinationSize + 2 + Ed25519SignatureLength // 457

	// MinDatagram3Overhead is the minimum envelope overhead for Datagram3.
	// fromhash(32) + flags(2) = 34 bytes (without options)
	//
	// Actual overhead may be larger when:
	// - Options field is present (adds 2+ bytes for mapping)
	MinDatagram3Overhead = 32 + 2 // 34
)

// DatagramConn represents a stateless I2P datagram connection that wraps an I2CP session.
// It implements net.PacketConn for compatibility with standard Go networking code.
//
// DatagramConn supports port-based message routing, allowing multiple application
// protocols to share a single I2CP session. Each connection is bound to a local port
// and can send/receive datagrams to/from remote I2P destinations and ports.
//
// Design decisions:
//   - Stateless: No connection tracking between sends, matching I2CP semantics
//   - Thread-safe: All methods safe for concurrent use via internal mutex
//   - Protocol-aware: Supports Raw (18), Datagram1 (17), Datagram2 (19), Datagram3 (20)
//   - Port-based: Port multiplexing on a single I2CP session
//
// Port-based routing:
// I2CP datagrams are raw byte payloads without built-in addressing. This library
// provides port-based routing to allow multiple services to share a single I2CP session.
// Applications that don't need ports can use Raw datagrams with zero overhead.
type DatagramConn struct {
	// session is the underlying I2CP session for sending/receiving datagrams.
	// Lifetime managed by caller - DatagramConn does not create or close the session.
	session I2CPSession

	// localDest is the I2P destination of this connection, obtained from the session.
	// This is our identity in the I2P network and is included in authenticated datagrams.
	localDest *i2cp.Destination

	// localPort is the UDP port number this connection is bound to.
	// Used for source port in outgoing packets and filtering incoming packets.
	localPort uint16

	// protocol specifies the I2P datagram type (17, 18, 19, or 20).
	// Determines packet format and overhead. Default is ProtocolRaw (18).
	protocol uint8

	// mu protects concurrent access to handlers and closed state.
	// RWMutex allows multiple concurrent readers (receives) with exclusive writers (register/close).
	mu sync.RWMutex

	// handlers maps destination ports to callback functions for incoming messages.
	// Enables port-based routing within a single I2CP session.
	// Protected by mu for thread-safe registration/unregistration.
	handlers map[uint16]func([]byte, *i2cp.Destination)

	// closed tracks whether Close() has been called.
	// Once closed, all operations return net.ErrClosed.
	closed bool

	// ctx is the context for canceling background operations (receive loop).
	// Created when connection is established, canceled in Close().
	ctx context.Context

	// cancel cancels the context, stopping the receive loop.
	cancel context.CancelFunc

	// wg tracks active handler goroutines for graceful shutdown.
	// Incremented when spawning handler, decremented when handler completes.
	wg sync.WaitGroup

	// receiveLoopStarted tracks if the background receive loop has been started.
	// The loop is lazily started on first handler registration.
	receiveLoopStarted bool

	// readDeadline is the deadline for read operations.
	// Zero value means no deadline.
	readDeadline time.Time

	// writeDeadline is the deadline for write operations.
	// Zero value means no deadline.
	writeDeadline time.Time

	// recvQueue is a buffered channel for incoming datagrams.
	// Messages are placed here by I2CP callbacks (Phase 3) or test injection.
	// ReceiveFrom() blocks on this channel.
	recvQueue chan *receivedDatagram
}

// receivedDatagram represents an incoming datagram with metadata.
type receivedDatagram struct {
	payload  []byte
	from     *i2cp.Destination
	fromHash [32]byte // SHA-256 hash of sender's destination (used by Datagram3)
	protocol uint8
	srcPort  uint16
	destPort uint16
}

// ReceiveResult contains the complete result of receiving a datagram,
// including optional fields like protocol-specific options.
//
// This struct is returned by [DatagramConn.ReceiveFromWithOptions] to provide
// access to all datagram information including the options field which is
// supported by Datagram2 (protocol 19) and Datagram3 (protocol 20).
//
// For protocols that don't support options (Raw, Datagram1), the Options
// field will be nil.
type ReceiveResult struct {
	// Payload is the application data extracted from the datagram.
	Payload []byte

	// From is the sender's full I2P destination for authenticated protocols.
	// For Datagram3 (protocol 20), this is nil because only the sender's hash
	// is available. Use FromHash or FromAddr.DestinationHash instead.
	From *i2cp.Destination

	// FromHash is the SHA-256 hash of the sender's destination.
	// Available for Datagram3 and computed from From for other protocols.
	FromHash [32]byte

	// FromAddr is the sender address as an I2PAddr for net.Addr compatibility.
	FromAddr *I2PAddr

	// SrcPort is the source port from the datagram header.
	SrcPort uint16

	// Options contains the I2P Mapping options if present in the datagram.
	// Only Datagram2 (19) and Datagram3 (20) support options.
	// This is nil for protocols that don't support options or when no options
	// were included in the received datagram.
	Options *Options
}

// NewDatagramConn creates a new DatagramConn bound to the specified local port.
// The connection uses ProtocolRaw (18) by default for zero overhead.
//
// The session parameter must be a valid, open I2CP session. The caller is responsible
// for session lifecycle management. DatagramConn will not close the session.
//
// The localPort parameter specifies the UDP port number for this connection.
// Port 0 is allowed but not recommended - it won't filter incoming packets by port.
//
// Design rationale:
//   - Default to Raw protocol for performance and simplicity
//   - Let caller manage session lifecycle (follows Go convention of explicit ownership)
//   - Require explicit port binding (no auto-assignment) for clarity
//
// Example:
//
//	session, _ := i2cp.NewSession(client, callbacks)
//	conn, err := datagrams.NewDatagramConn(session, 8080)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer conn.Close()
func NewDatagramConn(session I2CPSession, localPort uint16) (*DatagramConn, error) {
	return NewDatagramConnWithProtocol(session, localPort, ProtocolRaw)
}

// NewDatagramConnWithProtocol creates a new DatagramConn with a specific protocol type.
//
// The protocol parameter must be one of:
//   - ProtocolRaw (18): Non-repliable, no authentication, 0 bytes overhead
//   - ProtocolDatagram1 (17): Repliable, authenticated, ~455 bytes overhead (Ed25519)
//   - ProtocolDatagram2 (19): Repliable, authenticated with replay prevention, ~457+ bytes overhead (Ed25519)
//   - ProtocolDatagram3 (20): Repliable, non-authenticated, ~34 bytes overhead
//
// Protocol selection guide:
//   - Use Raw for high-performance, trusted communication
//   - Use Datagram3 for repliability with minimal overhead
//   - Use Datagram2 for authentication with replay attack prevention
//   - Use Datagram1 only for legacy compatibility
//
// Returns an error if:
//   - session is nil
//   - session is closed
//   - session destination cannot be retrieved
//   - protocol is ProtocolStreaming (6) which is reserved for streaming
func NewDatagramConnWithProtocol(session I2CPSession, localPort uint16, protocol uint8) (*DatagramConn, error) {
	if session == nil {
		return nil, fmt.Errorf("session cannot be nil")
	}

	if session.IsClosed() {
		return nil, fmt.Errorf("session is closed")
	}

	// Protocol 6 is reserved for I2P streaming and must not be used for datagrams.
	// Per I2P specification: "any other protocol numbers may be used other than
	// the streaming protocol number (6)".
	if protocol == ProtocolStreaming {
		return nil, fmt.Errorf("protocol %d (streaming) is reserved and cannot be used for datagrams", protocol)
	}

	localDest := session.Destination()
	if localDest == nil {
		return nil, fmt.Errorf("session has no destination")
	}

	ctx, cancel := context.WithCancel(context.Background())

	conn := &DatagramConn{
		session:            session,
		localDest:          localDest,
		localPort:          localPort,
		protocol:           protocol,
		handlers:           make(map[uint16]func([]byte, *i2cp.Destination)),
		closed:             false,
		ctx:                ctx,
		cancel:             cancel,
		recvQueue:          make(chan *receivedDatagram, 100), // Buffer 100 datagrams
		receiveLoopStarted: false,
	}

	return conn, nil
}

// Close closes the datagram connection and releases associated resources.
// It cancels any background operations (like the receive loop) and marks
// the connection as closed.
//
// Close does NOT close the underlying I2CP session - the caller must manage
// session lifecycle independently. This design allows multiple DatagramConns
// to share a single session (though currently only one is typical).
//
// After Close() is called, all subsequent operations on the connection will
// return net.ErrClosed. Close() is idempotent - calling it multiple times
// is safe and only the first call has effect.
//
// Close() is safe to call concurrently with other operations.
func (d *DatagramConn) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return nil // Already closed, idempotent
	}

	d.closed = true
	d.cancel() // Cancel context to stop receive loop

	// Clear handlers to help GC
	d.handlers = make(map[uint16]func([]byte, *i2cp.Destination))

	// Must release lock here: handler goroutines and receiveLoop may need RLock,
	// and wg.Wait() blocks until they complete. This is safe because d.closed is
	// already true above, so any concurrent operation will see the closed state
	// and return early. Re-acquire after Wait() to satisfy the deferred Unlock() above.
	d.mu.Unlock()

	// Wait for receiveLoop and all handler goroutines to complete (graceful shutdown)
	// This ensures no goroutines are accessing recvQueue when we close it
	d.wg.Wait()

	// Close receive queue to unblock any waiting ReceiveFrom() calls.
	// Safe to close now: receiveLoop has exited (tracked by wg), so no goroutine
	// will attempt to send on the channel.
	close(d.recvQueue)

	// Reacquire lock to satisfy deferred Unlock() at function entry
	d.mu.Lock()

	return nil
}

// IsClosed returns true if Close() has been called on this connection.
// This is a convenience method for checking connection state.
func (d *DatagramConn) IsClosed() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.closed
}

// LocalAddr returns the local network address.
// For I2P, this is an I2PAddr containing our destination and port.
//
// This implements the net.PacketConn interface.
func (d *DatagramConn) LocalAddr() net.Addr {
	// Use Base64() to get the destination's base64 address string.
	// This allows applications to identify and share their I2P address.
	var destStr string
	if d.localDest != nil {
		destStr = d.localDest.Base64()
	}
	return &I2PAddr{
		Destination: destStr,
		Port:        d.localPort,
	}
}

// SetDeadline sets both read and write deadlines for the connection.
// This implements the net.PacketConn interface.
//
// A zero value for t means no deadline. After a deadline has been reached,
// operations will fail with a timeout error.
//
// Note: Deadline support is currently basic - it sets both read and write
// deadlines to the same value. Use SetReadDeadline/SetWriteDeadline for
// independent control.
func (d *DatagramConn) SetDeadline(t time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return net.ErrClosed
	}

	d.readDeadline = t
	d.writeDeadline = t
	return nil
}

// SetReadDeadline sets the deadline for future Read operations.
// A zero value for t means no deadline.
//
// This implements the net.PacketConn interface.
func (d *DatagramConn) SetReadDeadline(t time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return net.ErrClosed
	}

	d.readDeadline = t
	return nil
}

// SetWriteDeadline sets the deadline for future Write operations.
// A zero value for t means no deadline.
//
// This implements the net.PacketConn interface.
func (d *DatagramConn) SetWriteDeadline(t time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return net.ErrClosed
	}

	d.writeDeadline = t
	return nil
}

// Protocol returns the I2P datagram protocol type (17, 18, 19, or 20).
// This allows inspecting which protocol the connection is using.
func (d *DatagramConn) Protocol() uint8 {
	return d.protocol
}

// HasSenderDestination returns true if ReceiveFrom() will return a usable sender destination.
//
// For Datagram3 (protocol 20), this returns false because the protocol only includes
// the sender's 32-byte hash, not the full destination. In this case, applications should
// use ReceiveFromWithAddr() instead to get the sender's hash via I2PAddr.DestinationHash.
//
// For all other protocols (Raw, Datagram1, Datagram2), this returns true.
//
// Example usage:
//
//	if conn.HasSenderDestination() {
//	    payload, from, port, err := conn.ReceiveFrom()
//	    // from is a valid destination
//	} else {
//	    payload, addr, err := conn.ReceiveFromWithAddr()
//	    // Use addr.DestinationHash to identify the sender
//	}
func (d *DatagramConn) HasSenderDestination() bool {
	return d.protocol != ProtocolDatagram3
}

// Session returns the underlying I2CP session.
// This allows advanced users to access session-level operations if needed.
func (d *DatagramConn) Session() I2CPSession {
	return d.session
}

// MaxPayloadSize returns the maximum payload size for this connection's protocol type.
// This accounts for protocol-specific overhead in the I2NP message.
//
// Protocol-specific limits (for Ed25519 destinations):
//   - Raw (18): 64KB - no envelope overhead
//   - Datagram3 (20): 64KB - 34 bytes (fromhash + flags)
//   - Datagram1 (17): 64KB - 455 bytes (dest(391) + signature(64))
//   - Datagram2 (19): 64KB - 457 bytes (dest(391) + flags(2) + signature(64))
//
// Note: The I2P spec uses "387+" for destination size (serialized format) and "40+"
// for signature (DSA_SHA1). This library uses Ed25519 exclusively, so:
//   - Destination wire format: 391 bytes (pubKey(256) + signingPubKey(128) + cert(7))
//   - Signature: 64 bytes (Ed25519)
//
// For reliable delivery, limit payloads to RecommendedMaxSize (~10KB) or less due to
// I2NP fragmentation into 1KB tunnel messages. Drop probability increases exponentially
// with message size.
func (d *DatagramConn) MaxPayloadSize() int {
	switch d.protocol {
	case ProtocolRaw:
		return MaxI2NPSize // No overhead for raw datagrams
	case ProtocolDatagram3:
		return MaxI2NPSize - MinDatagram3Overhead // fromhash(32) + flags(2) = 34
	case ProtocolDatagram1:
		return MaxI2NPSize - MinDatagram1Overhead // dest(391) + signature(64) = 455
	case ProtocolDatagram2:
		return MaxI2NPSize - MinDatagram2Overhead // dest(391) + flags(2) + signature(64) = 457
	default:
		return MaxI2NPSize // Conservative fallback
	}
}

// SendTo sends a datagram to the specified I2P destination and port.
//
// The payload is wrapped in a protocol-specific envelope based on the connection's
// protocol type:
//   - Raw (18): payload sent directly, no envelope
//   - Datagram3 (20): fromhash + flags + payload
//   - Datagram1 (17): from destination + signature + payload
//   - Datagram2 (19): from destination + flags + options + signature + payload
//
// The destination parameter should be a valid I2P destination string (base64 encoded).
// The port parameter is used for application-level routing within I2P.
//
// Returns an error if:
//   - The connection is closed
//   - The payload exceeds MaxPayloadSize()
//   - The write deadline has expired
//   - The underlying I2CP session fails to send
func (d *DatagramConn) SendTo(payload []byte, destinationB64 string, port uint16) error {
	d.mu.RLock()
	closed := d.closed
	deadline := d.writeDeadline
	protocol := d.protocol
	session := d.session
	localPort := d.localPort
	d.mu.RUnlock()

	if closed {
		return net.ErrClosed
	}

	// Validate payload size
	maxSize := d.MaxPayloadSize()
	if len(payload) > maxSize {
		return fmt.Errorf("payload size %d exceeds maximum %d for protocol %d", len(payload), maxSize, protocol)
	}

	// Check write deadline
	if !deadline.IsZero() && time.Now().After(deadline) {
		return fmt.Errorf("write deadline exceeded")
	}

	// Parse destination from base64 string
	// Note: go-i2cp NewDestinationFromBase64 requires a Crypto object
	// For now, we create a default one. In production, this should be
	// passed from the session or connection config.
	crypto := i2cp.NewCrypto()
	dest, err := i2cp.NewDestinationFromBase64(destinationB64, crypto)
	if err != nil {
		return fmt.Errorf("invalid destination: %w", err)
	}

	// Construct protocol-specific envelope
	var envelope []byte
	switch protocol {
	case ProtocolRaw:
		// Raw datagrams have no envelope, send payload directly
		envelope = payload

	case ProtocolDatagram3:
		// Datagram3: fromhash(32) + flags(2) + payload
		localDest := session.Destination()

		// Compute SHA-256 hash of the local destination
		fromHash, err := destinationHash(localDest)
		if err != nil {
			return fmt.Errorf("failed to compute destination hash: %w", err)
		}

		envelope = make([]byte, 32+2+len(payload))
		copy(envelope[0:32], fromHash[:])

		// flags: version 0x03 (bits 3-0), no options (bit 4 = 0)
		envelope[32] = 0x00
		envelope[33] = 0x03

		copy(envelope[34:], payload)

	case ProtocolDatagram1:
		// Datagram1: from dest(387+) + signature(40+) + payload
		var err error
		envelope, err = buildDatagram1Envelope(payload, session)
		if err != nil {
			return fmt.Errorf("failed to build Datagram1 envelope: %w", err)
		}

	case ProtocolDatagram2:
		// Datagram2: from dest(387+) + flags(2) + options(optional) + offline_sig(optional) + payload + signature(40+)
		// Compute target destination hash (needed for replay prevention)
		targetDestHash, err := destinationHash(dest)
		if err != nil {
			return fmt.Errorf("failed to compute target destination hash: %w", err)
		}

		envelope, err = buildDatagram2Envelope(payload, session, targetDestHash)
		if err != nil {
			return fmt.Errorf("failed to build Datagram2 envelope: %w", err)
		}

	default:
		return fmt.Errorf("unsupported protocol: %d", protocol)
	}

	// Send via I2CP
	// Note: I2CP NewStream takes a byte slice
	stream := i2cp.NewStream(envelope)

	// Use context with timeout if write deadline is set
	if !deadline.IsZero() {
		timeout := time.Until(deadline)
		if timeout <= 0 {
			return fmt.Errorf("write deadline exceeded")
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		err = session.SendMessageWithContext(ctx, dest, protocol, localPort, port, stream, 0)
	} else {
		err = session.SendMessage(dest, protocol, localPort, port, stream, 0)
	}

	if err != nil {
		return fmt.Errorf("failed to send datagram: %w", err)
	}

	return nil
}

// SendToWithOptions sends a datagram with optional I2P Mapping options.
//
// This method extends [DatagramConn.SendTo] by allowing the inclusion of options
// in the datagram envelope. Options are only supported by Datagram2 (protocol 19)
// and Datagram3 (protocol 20). For other protocols, the options parameter is ignored.
//
// Options can contain arbitrary key/value pairs encoded as an I2P Mapping structure.
// Common use cases include application-specific metadata, routing hints, or version info.
//
// The options parameter may be nil or empty to send a datagram without options
// (equivalent to calling [DatagramConn.SendTo]).
//
// Example:
//
//	opts := datagrams.NewOptions(map[string]string{
//	    "version": "1.0",
//	    "app": "myapp",
//	})
//	err := conn.SendToWithOptions(payload, destB64, port, opts)
//
// Returns an error if:
//   - The connection is closed
//   - The payload exceeds the maximum size for the protocol type
//   - The destination string is invalid
//   - The write deadline has expired
//   - The underlying I2CP session fails to send
func (d *DatagramConn) SendToWithOptions(payload []byte, destinationB64 string, port uint16, options *Options) error {
	d.mu.RLock()
	closed := d.closed
	deadline := d.writeDeadline
	protocol := d.protocol
	session := d.session
	localPort := d.localPort
	d.mu.RUnlock()

	if closed {
		return net.ErrClosed
	}

	// Calculate max payload accounting for options overhead
	maxSize := d.MaxPayloadSize()
	optionsOverhead := 0
	if options != nil && !options.IsEmpty() {
		optionsOverhead = options.Len()
	}
	effectiveMax := maxSize - optionsOverhead
	if effectiveMax < 0 {
		return fmt.Errorf("options too large: %d bytes, maximum payload %d", optionsOverhead, maxSize)
	}
	if len(payload) > effectiveMax {
		return fmt.Errorf("payload size %d exceeds maximum %d for protocol %d with options (%d bytes)", len(payload), effectiveMax, protocol, optionsOverhead)
	}

	// Check write deadline
	if !deadline.IsZero() && time.Now().After(deadline) {
		return fmt.Errorf("write deadline exceeded")
	}

	// Parse destination from base64 string
	crypto := i2cp.NewCrypto()
	dest, err := i2cp.NewDestinationFromBase64(destinationB64, crypto)
	if err != nil {
		return fmt.Errorf("invalid destination: %w", err)
	}

	// Construct protocol-specific envelope
	var envelope []byte
	switch protocol {
	case ProtocolRaw:
		// Raw datagrams don't support options, send payload directly
		envelope = payload

	case ProtocolDatagram3:
		// Datagram3: fromhash(32) + flags(2) + [options] + payload
		var buildErr error
		envelope, buildErr = buildDatagram3EnvelopeWithOptions(payload, session, options)
		if buildErr != nil {
			return fmt.Errorf("failed to build Datagram3 envelope: %w", buildErr)
		}

	case ProtocolDatagram1:
		// Datagram1 doesn't support options
		var buildErr error
		envelope, buildErr = buildDatagram1Envelope(payload, session)
		if buildErr != nil {
			return fmt.Errorf("failed to build Datagram1 envelope: %w", buildErr)
		}

	case ProtocolDatagram2:
		// Datagram2: from dest(387+) + flags(2) + [options] + [offline_sig] + payload + signature(40+)
		targetDestHash, err := destinationHash(dest)
		if err != nil {
			return fmt.Errorf("failed to compute target destination hash: %w", err)
		}

		var buildErr error
		envelope, buildErr = buildDatagram2EnvelopeWithOptions(payload, session, targetDestHash, options)
		if buildErr != nil {
			return fmt.Errorf("failed to build Datagram2 envelope: %w", buildErr)
		}

	default:
		return fmt.Errorf("unsupported protocol: %d", protocol)
	}

	// Send via I2CP
	stream := i2cp.NewStream(envelope)

	// Use context with timeout if write deadline is set
	if !deadline.IsZero() {
		timeout := time.Until(deadline)
		if timeout <= 0 {
			return fmt.Errorf("write deadline exceeded")
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		err = session.SendMessageWithContext(ctx, dest, protocol, localPort, port, stream, 0)
	} else {
		err = session.SendMessage(dest, protocol, localPort, port, stream, 0)
	}

	if err != nil {
		return fmt.Errorf("failed to send datagram: %w", err)
	}

	return nil
}

// ReceiveFrom receives a datagram and returns the payload, sender destination, and source port.
//
// This method blocks until a datagram is received or an error occurs. It respects the
// read deadline set by SetReadDeadline() or SetDeadline().
//
// The method parses protocol-specific envelopes:
//   - Raw (18): Payload is returned directly (no envelope)
//   - Datagram1 (17): Extracts from destination + signature, verifies signature, then payload
//   - Datagram2 (19): Extracts from + flags + signature, verifies with replay prevention, then payload
//   - Datagram3 (20): Extracts fromhash(32) + flags(2), then payload (see WARNING below)
//
// # WARNING: Datagram3 Sender Identification
//
// For Datagram3 (protocol 20), the returned sender destination is EMPTY because the
// protocol only includes a 32-byte hash of the sender's destination, not the full
// destination itself. If you need to identify the sender when using Datagram3:
//
//  1. Use [DatagramConn.ReceiveFromWithAddr] instead - it returns an [I2PAddr] containing
//     the sender's hash in DestinationHash field
//  2. Use [DatagramConn.HasSenderDestination] to check if this method will return a valid
//     destination before calling
//
// To reply to a Datagram3 sender, applications must look up the full destination from
// a cache or the I2P network database using the hash.
//
// Returns an error if:
//   - The connection is closed
//   - The read deadline has expired
//   - The envelope is malformed
//   - Signature verification fails (Datagram1/2)
func (d *DatagramConn) ReceiveFrom() ([]byte, *i2cp.Destination, uint16, error) {
	d.mu.RLock()
	closed := d.closed
	deadline := d.readDeadline
	protocol := d.protocol
	d.mu.RUnlock()

	if closed {
		return nil, nil, 0, net.ErrClosed
	}

	// Set up deadline timeout if specified
	var timer *time.Timer
	var timeoutChan <-chan time.Time
	if !deadline.IsZero() {
		timeout := time.Until(deadline)
		if timeout <= 0 {
			return nil, nil, 0, fmt.Errorf("read deadline exceeded")
		}
		timer = time.NewTimer(timeout)
		defer timer.Stop()
		timeoutChan = timer.C
	}

	// Block until message received, deadline, or context cancelled
	select {
	case msg := <-d.recvQueue:
		// Parse protocol-specific envelope
		return d.parseEnvelope(msg, protocol)

	case <-timeoutChan:
		return nil, nil, 0, fmt.Errorf("read deadline exceeded")

	case <-d.ctx.Done():
		return nil, nil, 0, net.ErrClosed
	}
}

// ReceiveFromWithAddr receives a datagram and returns the payload, sender address, and an error.
// This method provides more complete sender information than ReceiveFrom, including the
// destination hash for Datagram3 protocol messages.
//
// For Datagram3 (protocol 20), only the sender's destination hash is available in the
// protocol, not the full destination. Use addr.IsHashOnly() to check this condition.
// To reply to a Datagram3 sender, applications need to look up the full destination
// from a cache or the network database using addr.DestinationHash.
//
// This method blocks until a datagram is received or an error occurs. It respects the
// read deadline set by SetReadDeadline() or SetDeadline().
//
// Returns an error if:
//   - The connection is closed
//   - The read deadline has expired
//   - The envelope is malformed
func (d *DatagramConn) ReceiveFromWithAddr() ([]byte, *I2PAddr, error) {
	d.mu.RLock()
	closed := d.closed
	deadline := d.readDeadline
	protocol := d.protocol
	d.mu.RUnlock()

	if closed {
		return nil, nil, net.ErrClosed
	}

	// Set up deadline timeout if specified
	var timer *time.Timer
	var timeoutChan <-chan time.Time
	if !deadline.IsZero() {
		timeout := time.Until(deadline)
		if timeout <= 0 {
			return nil, nil, fmt.Errorf("read deadline exceeded")
		}
		timer = time.NewTimer(timeout)
		defer timer.Stop()
		timeoutChan = timer.C
	}

	// Block until message received, deadline, or context cancelled
	select {
	case msg := <-d.recvQueue:
		// Parse protocol-specific envelope and return as I2PAddr
		return d.parseEnvelopeToAddr(msg, protocol)

	case <-timeoutChan:
		return nil, nil, fmt.Errorf("read deadline exceeded")

	case <-d.ctx.Done():
		return nil, nil, net.ErrClosed
	}
}

// ReceiveFromWithOptions receives a datagram and returns a ReceiveResult containing
// the payload, sender information, and parsed options.
//
// This method provides complete access to all datagram fields, including the options
// field which is supported by Datagram2 (protocol 19) and Datagram3 (protocol 20).
//
// For protocols that don't support options (Raw, Datagram1), the Options field in the
// result will be nil. For protocols that support options but didn't include any in the
// received datagram, the Options field will also be nil.
//
// For Datagram3 (protocol 20), the From field in the result will be nil because only
// the sender's hash is available. Use FromHash or FromAddr.DestinationHash instead.
//
// This method blocks until a datagram is received or an error occurs. It respects the
// read deadline set by SetReadDeadline() or SetDeadline().
//
// Example:
//
//	result, err := conn.ReceiveFromWithOptions()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if result.Options != nil {
//	    version := result.Options.Get("version")
//	    log.Printf("Received from peer with version: %s", version)
//	}
//
// Returns an error if:
//   - The connection is closed
//   - The read deadline has expired
//   - The envelope is malformed
//   - Signature verification fails (Datagram1/2)
func (d *DatagramConn) ReceiveFromWithOptions() (*ReceiveResult, error) {
	d.mu.RLock()
	closed := d.closed
	deadline := d.readDeadline
	protocol := d.protocol
	d.mu.RUnlock()

	if closed {
		return nil, net.ErrClosed
	}

	// Set up deadline timeout if specified
	var timer *time.Timer
	var timeoutChan <-chan time.Time
	if !deadline.IsZero() {
		timeout := time.Until(deadline)
		if timeout <= 0 {
			return nil, fmt.Errorf("read deadline exceeded")
		}
		timer = time.NewTimer(timeout)
		defer timer.Stop()
		timeoutChan = timer.C
	}

	// Block until message received, deadline, or context cancelled
	select {
	case msg := <-d.recvQueue:
		// Parse protocol-specific envelope with options
		return d.parseEnvelopeWithOptions(msg, protocol)

	case <-timeoutChan:
		return nil, fmt.Errorf("read deadline exceeded")

	case <-d.ctx.Done():
		return nil, net.ErrClosed
	}
}

// parseEnvelope extracts the payload and sender information from a protocol-specific envelope.
func (d *DatagramConn) parseEnvelope(msg *receivedDatagram, protocol uint8) ([]byte, *i2cp.Destination, uint16, error) {
	switch protocol {
	case ProtocolRaw:
		// Raw datagrams have no envelope, payload is direct
		return msg.payload, msg.from, msg.srcPort, nil

	case ProtocolDatagram3:
		// Datagram3: fromhash(32) + flags(2) + [options] + payload
		// See SPEC.md for format details
		if len(msg.payload) < 34 {
			return nil, nil, 0, fmt.Errorf("Datagram3 envelope too short: %d bytes", len(msg.payload))
		}

		// Extract fromhash (first 32 bytes) - SHA-256 hash of sender's destination
		fromHash := msg.payload[0:32]

		// Extract flags per I2P Datagram specification:
		// Per spec: "flags :: (2 bytes) Bit order: 15 14 ... 3 2 1 0"
		// - High byte (index 32): reserved, currently unused (bits 8-15)
		// - Low byte (index 33): contains version (bits 0-3), options flag (bit 4), bits 5-7 reserved
		// See: https://geti2p.net/spec/datagrams#datagram3
		highFlags := msg.payload[32]
		lowFlags := msg.payload[33]

		// Validate reserved bits (5-15) are zero per spec:
		// "Bits 15-5: unused, set to 0 for compatibility with future uses"
		// High byte is entirely reserved; low byte bits 5-7 are reserved.
		reservedMask := uint16(0xFFE0) // bits 5-15
		flagsValue := uint16(highFlags)<<8 | uint16(lowFlags)
		if flagsValue&reservedMask != 0 {
			return nil, nil, 0, fmt.Errorf("Datagram3 has non-zero reserved flag bits: 0x%04x (reserved bits: 0x%04x)", flagsValue, flagsValue&reservedMask)
		}

		version := lowFlags & 0x0F
		hasOptions := (lowFlags & 0x10) != 0

		// Verify version bits (should be 0x03 for Datagram3)
		if version != 0x03 {
			return nil, nil, 0, fmt.Errorf("invalid Datagram3 version: 0x%x (expected 0x03)", version)
		}

		// Start of payload (after fromhash + flags)
		offset := 34

		// Parse options if present (I2P Mapping format: 2-byte size + key=value; pairs)
		if hasOptions {
			if len(msg.payload)-offset < 2 {
				return nil, nil, 0, fmt.Errorf("Datagram3 envelope too short for options size field at offset %d: have %d bytes, need at least 2", offset, len(msg.payload)-offset)
			}
			opts, optLen, optErr := OptionsFromBytes(msg.payload[offset:])
			if optErr != nil {
				return nil, nil, 0, fmt.Errorf("Datagram3 failed to parse options: %w", optErr)
			}
			offset += optLen
			// Options are parsed but not exposed in return value (could be added later)
			_ = opts
		}

		// Extract payload (everything after offset)
		payload := msg.payload[offset:]

		// Datagram3 only provides sender's hash, not full destination.
		// Return nil destination since no valid destination data is available.
		// Use ReceiveFromWithAddr() to get the sender's hash via I2PAddr.DestinationHash.
		_ = fromHash // Hash is available via ReceiveFromWithAddr()

		return payload, nil, msg.srcPort, nil

	case ProtocolDatagram1:
		// Datagram1: from dest(387+) + signature(40+) + payload
		payload, from, err := parseDatagram1Envelope(msg.payload, d.session)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("failed to parse Datagram1 envelope: %w", err)
		}
		return payload, from, msg.srcPort, nil

	case ProtocolDatagram2:
		// Datagram2: from dest(387+) + flags(2) + options(optional) + offline_sig(optional) + payload + signature(40+)
		payload, from, err := parseDatagram2Envelope(msg.payload, d.session)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("failed to parse Datagram2 envelope: %w", err)
		}
		return payload, from, msg.srcPort, nil

	default:
		return nil, nil, 0, fmt.Errorf("unsupported protocol for receive: %d", protocol)
	}
}

// parseEnvelopeToAddr extracts the payload and sender information from a protocol-specific envelope,
// returning the sender info as an I2PAddr for more complete representation including destination hash.
//
// This is particularly important for Datagram3 where only the sender's hash is available,
// not the full destination. The I2PAddr will have IsHashOnly() return true in this case.
func (d *DatagramConn) parseEnvelopeToAddr(msg *receivedDatagram, protocol uint8) ([]byte, *I2PAddr, error) {
	switch protocol {
	case ProtocolRaw:
		// Raw datagrams have no envelope, payload is direct
		// Note: Raw datagrams are not repliable - no sender info available
		addr := &I2PAddr{
			Port: msg.srcPort,
		}
		// If we have sender info (from I2CP metadata), populate it
		if msg.from != nil {
			addr.Destination = msg.from.Base64()
			if h, err := destinationHash(msg.from); err == nil {
				addr.DestinationHash = h
			}
		}
		return msg.payload, addr, nil

	case ProtocolDatagram3:
		// Datagram3: fromhash(32) + flags(2) + [options] + payload
		// See SPEC.md and https://geti2p.net/spec/datagrams#datagram3 for format details
		if len(msg.payload) < 34 {
			return nil, nil, fmt.Errorf("Datagram3 envelope too short: %d bytes, need at least 34", len(msg.payload))
		}

		// Extract fromhash (first 32 bytes) - SHA-256 hash of sender's destination
		var fromHash [32]byte
		copy(fromHash[:], msg.payload[0:32])

		// Extract flags per I2P Datagram specification:
		// Per spec: "flags :: (2 bytes) Bit order: 15 14 ... 3 2 1 0"
		// - High byte (index 32): reserved, currently unused
		// - Low byte (index 33): contains version (bits 0-3) and options flag (bit 4)
		// See: https://geti2p.net/spec/datagrams#datagram3
		lowFlags := msg.payload[33]
		version := lowFlags & 0x0F
		hasOptions := (lowFlags & 0x10) != 0

		// Verify version bits (should be 0x03 for Datagram3)
		if version != 0x03 {
			return nil, nil, fmt.Errorf("invalid Datagram3 version: 0x%x (expected 0x03)", version)
		}

		// Start of payload (after fromhash + flags)
		offset := 34

		// Parse options if present (I2P Mapping format: 2-byte size + key=value; pairs)
		if hasOptions {
			if len(msg.payload)-offset < 2 {
				return nil, nil, fmt.Errorf("Datagram3 envelope too short for options size field at offset %d: have %d bytes, need at least 2", offset, len(msg.payload)-offset)
			}
			opts, optLen, optErr := OptionsFromBytes(msg.payload[offset:])
			if optErr != nil {
				return nil, nil, fmt.Errorf("Datagram3 failed to parse options: %w", optErr)
			}
			offset += optLen
			// Options are parsed but not exposed in return value (could be added later)
			_ = opts
		}

		// Extract payload (everything after offset)
		payload := msg.payload[offset:]

		// Return I2PAddr with hash-only sender identification
		// Datagram3 protocol only provides the hash, not the full destination
		// Applications needing the full destination must look it up from netdb or cache
		addr := &I2PAddr{
			Destination:     "", // Not available in Datagram3 protocol
			DestinationHash: fromHash,
			Port:            msg.srcPort,
		}

		return payload, addr, nil

	case ProtocolDatagram1:
		// Datagram1: from dest(387+) + signature(40+) + payload
		payload, from, err := parseDatagram1Envelope(msg.payload, d.session)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse Datagram1 envelope: %w", err)
		}

		addr := &I2PAddr{
			Port: msg.srcPort,
		}
		if from != nil {
			addr.Destination = from.Base64()
			if h, err := destinationHash(from); err == nil {
				addr.DestinationHash = h
			}
		}
		return payload, addr, nil

	case ProtocolDatagram2:
		// Datagram2: from dest(387+) + flags(2) + options(optional) + offline_sig(optional) + payload + signature(40+)
		payload, from, err := parseDatagram2Envelope(msg.payload, d.session)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse Datagram2 envelope: %w", err)
		}

		addr := &I2PAddr{
			Port: msg.srcPort,
		}
		if from != nil {
			addr.Destination = from.Base64()
			if h, err := destinationHash(from); err == nil {
				addr.DestinationHash = h
			}
		}
		return payload, addr, nil

	default:
		return nil, nil, fmt.Errorf("unsupported protocol for receive: %d", protocol)
	}
}

// parseEnvelopeWithOptions extracts all datagram fields including options.
// This method returns a complete ReceiveResult with all available information.
func (d *DatagramConn) parseEnvelopeWithOptions(msg *receivedDatagram, protocol uint8) (*ReceiveResult, error) {
	result := &ReceiveResult{
		SrcPort: msg.srcPort,
	}

	switch protocol {
	case ProtocolRaw:
		// Raw datagrams have no envelope, payload is direct, no options
		result.Payload = msg.payload
		result.From = msg.from
		if msg.from != nil {
			result.FromAddr = &I2PAddr{
				Destination: msg.from.Base64(),
				Port:        msg.srcPort,
			}
			if h, err := destinationHash(msg.from); err == nil {
				result.FromHash = h
				result.FromAddr.DestinationHash = result.FromHash
			}
		}
		return result, nil

	case ProtocolDatagram3:
		// Datagram3: fromhash(32) + flags(2) + [options] + payload
		if len(msg.payload) < 34 {
			return nil, fmt.Errorf("Datagram3 envelope too short: %d bytes, need at least 34", len(msg.payload))
		}

		// Extract fromhash (first 32 bytes)
		copy(result.FromHash[:], msg.payload[0:32])

		// Extract flags
		highFlags := msg.payload[32]
		lowFlags := msg.payload[33]

		// Validate reserved bits (5-15) are zero
		reservedMask := uint16(0xFFE0)
		flagsValue := uint16(highFlags)<<8 | uint16(lowFlags)
		if flagsValue&reservedMask != 0 {
			return nil, fmt.Errorf("Datagram3 has non-zero reserved flag bits: 0x%04x", flagsValue)
		}

		version := lowFlags & 0x0F
		hasOptions := (lowFlags & 0x10) != 0

		if version != 0x03 {
			return nil, fmt.Errorf("invalid Datagram3 version: 0x%x (expected 0x03)", version)
		}

		offset := 34

		// Parse options if present
		if hasOptions {
			if len(msg.payload)-offset < 2 {
				return nil, fmt.Errorf("Datagram3 envelope too short for options at offset %d", offset)
			}
			opts, optLen, optErr := OptionsFromBytes(msg.payload[offset:])
			if optErr != nil {
				return nil, fmt.Errorf("Datagram3 failed to parse options: %w", optErr)
			}
			offset += optLen
			result.Options = opts
		}

		result.Payload = msg.payload[offset:]
		result.From = nil // Datagram3 only has hash, not full destination
		result.FromAddr = &I2PAddr{
			Destination:     "",
			DestinationHash: result.FromHash,
			Port:            msg.srcPort,
		}
		return result, nil

	case ProtocolDatagram1:
		// Datagram1 doesn't support options
		payload, from, err := parseDatagram1Envelope(msg.payload, d.session)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Datagram1 envelope: %w", err)
		}
		result.Payload = payload
		result.From = from
		if from != nil {
			result.FromAddr = &I2PAddr{
				Destination: from.Base64(),
				Port:        msg.srcPort,
			}
			if h, err := destinationHash(from); err == nil {
				result.FromHash = h
				result.FromAddr.DestinationHash = result.FromHash
			}
		}
		return result, nil

	case ProtocolDatagram2:
		// Datagram2: parse with options support
		payload, from, opts, err := parseDatagram2EnvelopeWithOptions(msg.payload, d.session)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Datagram2 envelope: %w", err)
		}
		result.Payload = payload
		result.From = from
		result.Options = opts
		if from != nil {
			result.FromAddr = &I2PAddr{
				Destination: from.Base64(),
				Port:        msg.srcPort,
			}
			if h, err := destinationHash(from); err == nil {
				result.FromHash = h
				result.FromAddr.DestinationHash = result.FromHash
			}
		}
		return result, nil

	default:
		return nil, fmt.Errorf("unsupported protocol for receive: %d", protocol)
	}
}

// ReadFrom reads a packet from the connection, copying the payload into p.
// It returns the number of bytes copied into p and the return address that
// sent the packet.
//
// This implements the net.PacketConn interface by wrapping ReceiveFrom().
//
// ReadFrom can be made to time out and return an error after a fixed
// time limit; see SetDeadline and SetReadDeadline.
//
// Design notes:
//   - Wraps ReceiveFrom() to provide standard net.PacketConn semantics
//   - Converts I2P destination + port to I2PAddr for interface compliance
//   - Copies payload into provided buffer (standard Go networking pattern)
//   - Returns short read if buffer is too small (no error, matches UDP behavior)
//
// Returns an error if:
//   - The connection is closed (net.ErrClosed)
//   - The read deadline has expired
//   - The underlying receive operation fails
func (d *DatagramConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	// Call ReceiveFrom to get the datagram
	payload, from, srcPort, err := d.ReceiveFrom()
	if err != nil {
		return 0, nil, err
	}

	// Copy payload into provided buffer
	n = copy(p, payload)

	// Convert I2P destination + port to I2PAddr
	// Use Base64() to get the sender's base64 address string.
	// This allows applications to reply to the sender.
	var destStr string
	if from != nil {
		destStr = from.Base64()
	}
	i2pAddr := &I2PAddr{
		Destination: destStr,
		Port:        srcPort,
	}

	// If buffer was too small, we still return the bytes copied (not an error)
	// This matches the behavior of net.UDPConn and other PacketConn implementations
	return n, i2pAddr, nil
}

// WriteTo writes a packet with payload p to addr.
// WriteTo can be made to time out and return an error after a fixed
// time limit; see SetDeadline and SetWriteDeadline.
//
// This implements the net.PacketConn interface by wrapping SendTo().
//
// On packet-oriented connections, write timeouts are rare because
// writes are atomic operations. However, I2P datagrams may experience
// write delays due to router congestion or tunnel building.
//
// Design notes:
//   - Wraps SendTo() to provide standard net.PacketConn semantics
//   - Type-asserts net.Addr to I2PAddr for destination extraction
//   - Returns full payload length on success (atomic write)
//   - Validates address type before attempting send
//
// Returns an error if:
//   - addr is not of type *I2PAddr
//   - addr has an empty destination string
//   - The connection is closed (net.ErrClosed)
//   - The write deadline has expired
//   - The underlying send operation fails
func (d *DatagramConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// Type-assert addr to *I2PAddr
	i2pAddr, ok := addr.(*I2PAddr)
	if !ok {
		return 0, fmt.Errorf("address must be *I2PAddr, got %T", addr)
	}

	// Validate destination is not empty
	if i2pAddr.Destination == "" {
		return 0, fmt.Errorf("destination address is empty")
	}

	// Call SendTo with extracted destination and port
	err = d.SendTo(p, i2pAddr.Destination, i2pAddr.Port)
	if err != nil {
		return 0, err
	}

	// On success, return the full length of the payload
	// This matches the behavior of net.UDPConn (atomic write)
	return len(p), nil
}
