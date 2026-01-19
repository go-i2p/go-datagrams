package datagrams

import (
	"context"
	"crypto/sha256"
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

// Protocol numbers for I2P datagram types as defined in the I2P specification.
// See SPEC.md for detailed format specifications.
const (
	// ProtocolRaw (18) is for non-repliable, non-authenticated datagrams.
	// Zero overhead, highest performance. Use for trusted peers or when
	// authentication is handled at the application layer.
	ProtocolRaw uint8 = 18

	// ProtocolDatagram1 (17) is for repliable, authenticated datagrams (legacy).
	// ~427 bytes overhead. Use for compatibility with older I2P applications.
	ProtocolDatagram1 uint8 = 17

	// ProtocolDatagram2 (19) is for repliable, authenticated datagrams with replay prevention.
	// ~433+ bytes overhead. Use for modern authenticated messaging requiring
	// protection against replay attacks.
	ProtocolDatagram2 uint8 = 19

	// ProtocolDatagram3 (20) is for repliable, non-authenticated datagrams.
	// ~34 bytes overhead. Use when repliability is needed with minimal overhead
	// and authentication is not required.
	ProtocolDatagram3 uint8 = 20
)

// Size constants for I2P datagrams.
const (
	// MaxI2NPSize is the nominal maximum size for I2NP messages including datagrams.
	MaxI2NPSize = 64 * 1024 // 64 KB

	// RecommendedMaxSize is the recommended maximum payload size for reliable delivery.
	// I2NP messages fragment into 1KB tunnel messages, and drop probability increases
	// exponentially with size. This limit ensures good reliability.
	RecommendedMaxSize = 10 * 1024 // 10 KB

	// OptimalMaxSize is the optimal payload size for best reliability.
	// Keeping messages small reduces fragmentation and improves delivery probability.
	OptimalMaxSize = 4 * 1024 // 4 KB
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
	protocol uint8
	srcPort  uint16
	destPort uint16
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
//   - ProtocolDatagram1 (17): Repliable, authenticated, ~427 bytes overhead (legacy)
//   - ProtocolDatagram2 (19): Repliable, authenticated with replay prevention, ~433+ bytes overhead
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
//   - protocol is invalid (though any uint8 is technically allowed)
func NewDatagramConnWithProtocol(session I2CPSession, localPort uint16, protocol uint8) (*DatagramConn, error) {
	if session == nil {
		return nil, fmt.Errorf("session cannot be nil")
	}

	if session.IsClosed() {
		return nil, fmt.Errorf("session is closed")
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

	// Close receive queue to unblock any waiting ReceiveFrom() calls
	close(d.recvQueue)

	// Clear handlers to help GC
	d.handlers = make(map[uint16]func([]byte, *i2cp.Destination))

	// Release lock before waiting (handlers may need to acquire RLock)
	d.mu.Unlock()

	// Wait for all handler goroutines to complete (graceful shutdown)
	// This ensures no handlers are running when Close() returns
	d.wg.Wait()

	// Reacquire lock to maintain defer unlock semantics
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

// Session returns the underlying I2CP session.
// This allows advanced users to access session-level operations if needed.
func (d *DatagramConn) Session() I2CPSession {
	return d.session
}

// MaxPayloadSize returns the maximum payload size for this connection's protocol type.
// This accounts for protocol-specific overhead in the I2NP message.
//
// Protocol-specific limits:
//   - Raw (18): ~64KB - minimal overhead
//   - Datagram3 (20): ~64KB - 34 bytes (fromhash + flags)
//   - Datagram1 (17): ~64KB - 427+ bytes (from dest + signature)
//   - Datagram2 (19): ~64KB - 433+ bytes (from dest + flags + signature + options)
//
// Note: For reliable delivery, limit payloads to ~10KB or less due to I2NP
// fragmentation into 1KB tunnel messages. Drop probability increases exponentially
// with message size.
func (d *DatagramConn) MaxPayloadSize() int {
	const maxI2NPSize = 64 * 1024 // 64 KB nominal I2NP message limit

	switch d.protocol {
	case ProtocolRaw:
		return maxI2NPSize // No overhead for raw datagrams
	case ProtocolDatagram3:
		return maxI2NPSize - 34 // fromhash(32) + flags(2)
	case ProtocolDatagram1:
		return maxI2NPSize - 427 // from dest(387) + signature(40+)
	case ProtocolDatagram2:
		return maxI2NPSize - 433 // from dest(387) + flags(2) + signature(40+) + minimal options
	default:
		return maxI2NPSize // Conservative fallback
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
		// The destination is serialized as: pubKey + signPubKey + cert
		destStream := i2cp.NewStream(nil)
		if err := localDest.WriteToStream(destStream); err != nil {
			return fmt.Errorf("failed to serialize destination: %w", err)
		}
		fromHash := sha256.Sum256(destStream.Bytes())

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
		targetDestStream := i2cp.NewStream(nil)
		if err := dest.WriteToStream(targetDestStream); err != nil {
			return fmt.Errorf("failed to serialize target destination: %w", err)
		}
		targetDestHash := sha256.Sum256(targetDestStream.Bytes())

		var err error
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

// ReceiveFrom receives a datagram and returns the payload, sender destination, and source port.
//
// This method blocks until a datagram is received or an error occurs. It respects the
// read deadline set by SetReadDeadline() or SetDeadline().
//
// The method parses protocol-specific envelopes:
//   - Raw (18): Payload is returned directly (no envelope)
//   - Datagram3 (20): Extracts fromhash(32) + flags(2), then payload
//   - Datagram1 (17): Extracts from destination + signature, then payload (TODO)
//   - Datagram2 (19): Extracts from + flags + signature, then payload (TODO)
//
// Returns an error if:
//   - The connection is closed
//   - The read deadline has expired
//   - The envelope is malformed
//
// Note: For MVP, this method reads from an internal queue that must be populated by
// test injection or I2CP callbacks. Phase 3 will add automatic population via I2CP.
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

		// Extract flags following Java pattern (Datagram3.java):
		// - High byte (index 32): ignored per spec
		// - Low byte (index 33): contains version (bits 0-3) and options flag (bit 4)
		// This matches the Java reference: "in.read(); // ignore high byte, int flags = in.read();"
		// highFlags := msg.payload[32] // ignored per spec
		lowFlags := msg.payload[33]
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
				return nil, nil, 0, fmt.Errorf("Datagram3 envelope too short for options size field")
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

		// For now, create a minimal destination wrapper with just the hash
		// In a real implementation, we'd need to look up the full destination
		// from the network database or cache
		from := &i2cp.Destination{}
		_ = fromHash // TODO: Proper destination resolution in Phase 3

		return payload, from, msg.srcPort, nil

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

// Ed25519SignatureLength is the fixed signature length for Ed25519 (64 bytes).
// go-i2cp exclusively uses Ed25519, so this is constant.
const Ed25519SignatureLength = 64

// buildDatagram1Envelope constructs a Datagram1 envelope with signature.
// Format: from destination (387+ bytes) + signature (64 bytes for Ed25519) + payload
//
// Per I2P specification:
// - For DSA_SHA1 signature type (legacy): Signs the SHA-256 hash of the payload
// - For Ed25519 (modern): Signs the payload directly
//
// Since go-i2cp exclusively uses Ed25519, this implementation always signs the payload directly.
//
// IMPORTANT: Per I2P specification, Datagram1 does NOT support offline signatures (LS2 offline keys).
// Sessions with offline keys should use Datagram2 instead. This implementation cannot currently
// detect offline keys as go-i2cp doesn't expose this information at the Session level.
// See: https://geti2p.net/spec/datagrams#notes and Java I2PDatagramMaker.java
//
// Returns the complete envelope or an error if signing fails.
func buildDatagram1Envelope(payload []byte, session I2CPSession) ([]byte, error) {
	// NOTE: Per spec, Datagram1 does NOT support offline signatures.
	// The Java reference implementation (I2PDatagramMaker) throws IllegalArgumentException
	// if session.isOffline() returns true. However, go-i2cp currently doesn't expose
	// an IsOffline() method on Session, so we cannot perform this check.
	// TODO: Add IsOffline() check when go-i2cp exposes this method.
	// For now, users with offline keys should use Datagram2 (protocol 19).

	// Get the session's signing key pair
	keyPair, err := session.SigningKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to get signing key pair: %w", err)
	}

	// Get the local destination to include in the envelope
	localDest := session.Destination()
	if localDest == nil {
		return nil, fmt.Errorf("session has no destination")
	}

	// Serialize the destination using wire format (WriteToMessage)
	// Wire format: pubKey(256) + signingPubKey(128) + certificate = 391+ bytes
	destStream := i2cp.NewStream(nil)
	if err := localDest.WriteToMessage(destStream); err != nil {
		return nil, fmt.Errorf("failed to serialize destination: %w", err)
	}
	destBytes := destStream.Bytes()

	// Sign the payload (Ed25519 signs directly, not the hash)
	signature, err := keyPair.Sign(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %w", err)
	}

	// Build envelope: destination + signature + payload
	envelope := make([]byte, len(destBytes)+len(signature)+len(payload))
	copy(envelope[0:], destBytes)
	copy(envelope[len(destBytes):], signature)
	copy(envelope[len(destBytes)+len(signature):], payload)

	return envelope, nil
}

// parseDatagram1Envelope extracts and verifies a Datagram1 envelope.
// Format: from destination (391+ bytes wire format) + signature (64 bytes for Ed25519) + payload
//
// The signature is verified using the sender's public key embedded in the destination.
// Returns the payload, from destination, and any error (including signature verification failure).
func parseDatagram1Envelope(data []byte, session I2CPSession) (payload []byte, from *i2cp.Destination, err error) {
	// Minimum size: wire format destination (256+128+7 = 391 bytes) + Ed25519 signature (64 bytes)
	const minSize = 391 + Ed25519SignatureLength
	if len(data) < minSize {
		return nil, nil, fmt.Errorf("Datagram1 envelope too short: %d bytes (need at least %d)", len(data), minSize)
	}

	// Parse destination from the envelope using wire format reader
	crypto := i2cp.NewCrypto()
	stream := i2cp.NewStream(data)
	from, err = i2cp.NewDestinationFromMessage(stream, crypto)
	if err != nil {
		return nil, nil, fmt.Errorf("Datagram1 failed to parse destination: %w", err)
	}

	// Calculate how many bytes were consumed by the destination (wire format)
	destStream := i2cp.NewStream(nil)
	if err := from.WriteToMessage(destStream); err != nil {
		return nil, nil, fmt.Errorf("Datagram1 failed to serialize destination: %w", err)
	}
	destLen := destStream.Len()

	// Check if there's enough data for signature + at least empty payload
	if len(data) < destLen+Ed25519SignatureLength {
		return nil, nil, fmt.Errorf("Datagram1 envelope too short after destination: %d bytes remaining (need at least %d for signature)", len(data)-destLen, Ed25519SignatureLength)
	}

	// Extract Ed25519 signature (fixed 64 bytes)
	signature := data[destLen : destLen+Ed25519SignatureLength]
	payload = data[destLen+Ed25519SignatureLength:]

	// Verify signature using the sender's destination public key
	// Per I2P spec: Ed25519 signs the payload directly (not the hash)
	if !from.VerifySignature(payload, signature) {
		return nil, nil, fmt.Errorf("Datagram1 signature verification failed")
	}

	return payload, from, nil
}

// buildDatagram2Envelope constructs a Datagram2 envelope with signature and replay prevention.
// Format: from destination (391+ bytes wire format) + flags (2 bytes) + [options] + payload + signature (64 bytes)
//
// The signature is computed over: target_dest_hash (32 bytes, not in datagram) + flags + [options] + payload
//
// Per I2P specification, the target destination hash provides replay prevention - the same
// signed payload sent to different destinations will have different valid signatures.
//
// This implementation supports Datagram2 with optional options (I2P Mapping format).
// Options may be nil or empty for datagrams without options.
// Returns the complete envelope or an error if signing fails.
func buildDatagram2Envelope(payload []byte, session I2CPSession, targetDestHash [32]byte) ([]byte, error) {
	return buildDatagram2EnvelopeWithOptions(payload, session, targetDestHash, nil)
}

// buildDatagram2EnvelopeWithOptions constructs a Datagram2 envelope with optional options field.
// Options may be nil or empty to omit the options field.
func buildDatagram2EnvelopeWithOptions(payload []byte, session I2CPSession, targetDestHash [32]byte, options *Options) ([]byte, error) {
	// Get the session's signing key pair
	keyPair, err := session.SigningKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to get signing key pair: %w", err)
	}

	// Get the local destination to include in the envelope
	localDest := session.Destination()
	if localDest == nil {
		return nil, fmt.Errorf("session has no destination")
	}

	// Serialize the destination using wire format (WriteToMessage)
	// Wire format: pubKey(256) + signingPubKey(128) + certificate = 391+ bytes
	destStream := i2cp.NewStream(nil)
	if err := localDest.WriteToMessage(destStream); err != nil {
		return nil, fmt.Errorf("failed to serialize destination: %w", err)
	}
	destBytes := destStream.Bytes()

	// Build flags (2 bytes): version 0x02, options flag if options present
	// Bit order: 15 14 ... 3 2 1 0
	// Bits 3-0: Version = 0x02
	// Bit 4: Options flag = 1 if options present
	// Bit 5: Offline signature flag = 0 (not supported for sending)
	lowFlags := byte(0x02) // version 0x02
	var optionsBytes []byte
	if options != nil && !options.IsEmpty() {
		lowFlags |= 0x10 // set options flag
		var optErr error
		optionsBytes, optErr = options.Bytes()
		if optErr != nil {
			return nil, fmt.Errorf("failed to serialize options: %w", optErr)
		}
	}
	flags := []byte{0x00, lowFlags} // high byte = 0, low byte = version + flags

	// Build data to sign: targetDestHash + flags + options + payload
	// Per spec: "The signature is over the following fields:
	// 1. Prelude: The 32-byte hash of the target destination (not included in the datagram)
	// 2. flags
	// 3. options (if present)
	// 4. offline_signature (if present) - not present in this implementation
	// 5. payload"
	toSign := make([]byte, 32+2+len(optionsBytes)+len(payload))
	offset := 0
	copy(toSign[offset:], targetDestHash[:])
	offset += 32
	copy(toSign[offset:], flags)
	offset += 2
	if len(optionsBytes) > 0 {
		copy(toSign[offset:], optionsBytes)
		offset += len(optionsBytes)
	}
	copy(toSign[offset:], payload)

	// Sign with Ed25519 (always signs directly, not the hash)
	signature, err := keyPair.Sign(toSign)
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %w", err)
	}

	// Build envelope: destination + flags + options + payload + signature
	// Note: signature is at the END for Datagram2 (unlike Datagram1 where it's in the middle)
	envelope := make([]byte, len(destBytes)+2+len(optionsBytes)+len(payload)+len(signature))
	envOffset := 0
	copy(envelope[envOffset:], destBytes)
	envOffset += len(destBytes)
	copy(envelope[envOffset:], flags)
	envOffset += 2
	if len(optionsBytes) > 0 {
		copy(envelope[envOffset:], optionsBytes)
		envOffset += len(optionsBytes)
	}
	copy(envelope[envOffset:], payload)
	envOffset += len(payload)
	copy(envelope[envOffset:], signature)

	return envelope, nil
}

// parseDatagram2Envelope extracts and verifies a Datagram2 envelope with replay prevention.
// Format: from destination (391+ bytes wire format) + flags (2 bytes) + [options] + [offline_sig] + payload + signature (64 bytes)
//
// The signature must verify against: receiver_dest_hash + flags + options + offline_sig + payload
// This provides replay prevention - datagrams sent to different destinations will fail verification.
//
// Optional fields:
//   - Options: I2P Mapping format when HEADER_OPTIONS flag (bit 4) is set
//   - Offline Signature: OfflineSignature block when HEADER_OFFLINE_SIG flag (bit 5) is set
//
// Returns the payload, from destination, and any error (including signature verification failure).
func parseDatagram2Envelope(data []byte, session I2CPSession) (payload []byte, from *i2cp.Destination, err error) {
	// Minimum size: wire format destination (391 bytes) + flags (2 bytes) + Ed25519 signature (64 bytes)
	const minSize = 391 + 2 + Ed25519SignatureLength
	if len(data) < minSize {
		return nil, nil, fmt.Errorf("Datagram2 envelope too short: %d bytes (need at least %d)", len(data), minSize)
	}

	// Parse destination from the envelope using wire format reader
	crypto := i2cp.NewCrypto()
	stream := i2cp.NewStream(data)
	from, err = i2cp.NewDestinationFromMessage(stream, crypto)
	if err != nil {
		return nil, nil, fmt.Errorf("Datagram2 failed to parse destination: %w", err)
	}

	// Calculate how many bytes were consumed by the destination (wire format)
	destStream := i2cp.NewStream(nil)
	if err := from.WriteToMessage(destStream); err != nil {
		return nil, nil, fmt.Errorf("Datagram2 failed to serialize destination: %w", err)
	}
	destLen := destStream.Len()

	// Check minimum remaining size for flags + signature
	if len(data) < destLen+2+Ed25519SignatureLength {
		return nil, nil, fmt.Errorf("Datagram2 envelope too short after destination: %d bytes remaining", len(data)-destLen)
	}

	// Extract flags (2 bytes)
	flags := data[destLen : destLen+2]

	// Parse flags - version is in low byte (bits 0-3)
	version := flags[1] & 0x0F
	if version != 0x02 {
		return nil, nil, fmt.Errorf("invalid Datagram2 version: 0x%x (expected 0x02)", version)
	}

	hasOptions := (flags[1] & 0x10) != 0
	hasOfflineSig := (flags[1] & 0x20) != 0

	offset := destLen + 2

	// Track optional field bytes for signature verification
	var optionsBytes []byte
	var offlineSigBytes []byte

	// Parse options if present (I2P Mapping format: 2-byte size + key=value; pairs)
	if hasOptions {
		if len(data)-offset < 2 {
			return nil, nil, fmt.Errorf("Datagram2 envelope too short for options size field")
		}
		opts, optLen, optErr := OptionsFromBytes(data[offset:])
		if optErr != nil {
			return nil, nil, fmt.Errorf("Datagram2 failed to parse options: %w", optErr)
		}
		// Store the raw options bytes for signature verification
		optionsBytes = data[offset : offset+optLen]
		offset += optLen
		// Options are parsed but not exposed in return value (could be added later)
		_ = opts
	}

	// Parse offline signature if present
	// Format: expires(4) + sigtype(2) + transient_public_key(variable) + signature(variable)
	var offlineSig *OfflineSignature
	if hasOfflineSig {
		// Need to know the destination's signature type for offline sig parsing
		// Ed25519 (sigtype 7) is the default for go-i2cp destinations
		destSigType := uint16(7) // Ed25519

		var offLen int
		var offErr error
		offlineSig, offLen, offErr = OfflineSignatureFromBytes(data[offset:], destSigType)
		if offErr != nil {
			return nil, nil, fmt.Errorf("Datagram2 failed to parse offline signature: %w", offErr)
		}

		// Check if the offline signature has expired
		if offlineSig.IsExpired() {
			return nil, nil, fmt.Errorf("Datagram2 offline signature has expired (expired at %s)", offlineSig.Expires)
		}

		// Verify the offline signature against the sender's destination key
		// This proves the destination authorized the transient key to sign on its behalf
		if verifyErr := offlineSig.Verify(from); verifyErr != nil {
			return nil, nil, fmt.Errorf("Datagram2 offline signature authorization failed: %w", verifyErr)
		}

		// Store the raw offline signature bytes for signature verification
		offlineSigBytes = data[offset : offset+offLen]
		offset += offLen
	}

	// Remaining data: payload + signature
	// Ed25519 signature is always 64 bytes and is at the END
	if len(data)-offset < Ed25519SignatureLength {
		return nil, nil, fmt.Errorf("Datagram2 envelope too short for signature")
	}

	// Split payload and signature (signature is at end)
	payloadEnd := len(data) - Ed25519SignatureLength
	payload = data[offset:payloadEnd]
	signature := data[payloadEnd:]

	// Get receiver's destination hash (our local destination) for replay prevention verification
	// Per spec: "The 32-byte hash of the target destination (not included in the datagram)"
	localDest := session.Destination()
	if localDest == nil {
		return nil, nil, fmt.Errorf("session has no destination for verification")
	}

	// Hash the wire format of our destination to get the target hash
	localDestStream := i2cp.NewStream(nil)
	if err := localDest.WriteToMessage(localDestStream); err != nil {
		return nil, nil, fmt.Errorf("Datagram2 failed to serialize local destination: %w", err)
	}
	localDestHash := sha256.Sum256(localDestStream.Bytes())

	// Build data that was signed: targetDestHash + flags + options + offline_sig + payload
	// Per I2P spec, signature covers all fields in order
	toVerifyLen := 32 + 2 + len(optionsBytes) + len(offlineSigBytes) + len(payload)
	toVerify := make([]byte, toVerifyLen)
	verifyOffset := 0
	copy(toVerify[verifyOffset:], localDestHash[:])
	verifyOffset += 32
	copy(toVerify[verifyOffset:], flags)
	verifyOffset += 2
	if len(optionsBytes) > 0 {
		copy(toVerify[verifyOffset:], optionsBytes)
		verifyOffset += len(optionsBytes)
	}
	if len(offlineSigBytes) > 0 {
		copy(toVerify[verifyOffset:], offlineSigBytes)
		verifyOffset += len(offlineSigBytes)
	}
	copy(toVerify[verifyOffset:], payload)

	// Verify signature using appropriate key:
	// - If offline signature present: use transient key from offline signature
	// - Otherwise: use sender's destination public key
	var signatureValid bool
	if offlineSig != nil {
		// Use the transient key for payload signature verification
		// The transient key was already validated against the destination's key above
		signatureValid = offlineSig.VerifyPayloadSignature(toVerify, signature)
	} else {
		// Standard verification using sender's destination key
		signatureValid = from.VerifySignature(toVerify, signature)
	}

	if !signatureValid {
		return nil, nil, fmt.Errorf("Datagram2 signature verification failed (possible replay attack or wrong recipient)")
	}

	return payload, from, nil
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

// RegisterPort registers a handler function for incoming datagrams on the specified port.
//
// When a datagram is received with a destination port matching the registered port,
// the handler function will be called with the payload and source destination.
// This enables port-based multiplexing of multiple application protocols on a single
// I2CP session.
//
// Design notes:
//   - Thread-safe: Uses RWMutex to protect the handlers map
//   - Error on duplicate: Returns error if port is already registered
//   - Handler dispatch: Will be called by background receive loop (Phase 3)
//   - Concurrent handlers: Each handler may be called concurrently (goroutine-safe required)
//
// Handler function signature:
//   - payload: The datagram payload bytes (after envelope parsing)
//   - from: The I2P destination of the sender (may be nil for Raw datagrams)
//
// Returns an error if:
//   - The connection is closed
//   - The port is already registered
//   - The handler function is nil
//
// Example:
//
//	conn.RegisterPort(8080, func(payload []byte, from *i2cp.Destination) {
//	    fmt.Printf("Received %d bytes from %s\n", len(payload), from)
//	})
func (d *DatagramConn) RegisterPort(port uint16, handler func([]byte, *i2cp.Destination)) error {
	if handler == nil {
		return fmt.Errorf("handler cannot be nil")
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return net.ErrClosed
	}

	// Check if port is already registered
	if _, exists := d.handlers[port]; exists {
		return fmt.Errorf("port %d already registered", port)
	}

	// Register the handler
	d.handlers[port] = handler

	// Start receive loop on first handler registration
	if !d.receiveLoopStarted {
		d.receiveLoopStarted = true
		go d.receiveLoop()
	}

	return nil
}

// UnregisterPort removes the handler for the specified port.
//
// After unregistration, datagrams received on this port will no longer
// trigger the handler callback. This is useful for graceful shutdown or
// dynamic port management.
//
// Design notes:
//   - Thread-safe: Uses RWMutex to protect the handlers map
//   - No-op if not registered: Does not return error if port not registered
//   - Immediate effect: Handler won't be called for subsequent receives
//
// Returns an error if:
//   - The connection is closed
//
// Example:
//
//	conn.UnregisterPort(8080)
func (d *DatagramConn) UnregisterPort(port uint16) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return net.ErrClosed
	}

	// Remove handler (no-op if doesn't exist)
	delete(d.handlers, port)
	return nil
}

// injectMessage is a helper method for testing that injects a received datagram
// into the receive queue. This simulates receiving a message from I2CP.
//
// In production (Phase 3), this will be called by I2CP message callbacks.
// For now, it's used by tests to verify receive functionality.
//
// Returns an error if the connection is closed or the queue is full.
func (d *DatagramConn) injectMessage(payload []byte, from *i2cp.Destination, protocol uint8, srcPort, destPort uint16) error {
	d.mu.RLock()
	closed := d.closed
	d.mu.RUnlock()

	if closed {
		return net.ErrClosed
	}

	msg := &receivedDatagram{
		payload:  payload,
		from:     from,
		protocol: protocol,
		srcPort:  srcPort,
		destPort: destPort,
	}

	// Non-blocking send to queue
	select {
	case d.recvQueue <- msg:
		return nil
	default:
		return fmt.Errorf("receive queue full")
	}
}

// receiveLoop continuously monitors incoming datagrams and dispatches to registered handlers.
// This method runs in a background goroutine spawned by the constructor.
//
// Design:
//   - Monitors recvQueue for incoming datagrams
//   - Looks up handler by destination port from received datagram
//   - If handler registered, consumes message and dispatches to handler in new goroutine (non-blocking)
//   - If no handler, leaves message in queue for manual ReadFrom/ReceiveFrom
//   - Terminates when context is canceled (in Close())
//   - Handles receive errors gracefully without crashing
//
// Thread safety:
//   - Uses RLock for handler lookup (allows concurrent receives)
//   - Each handler runs in separate goroutine to avoid blocking
//   - WaitGroup tracks handler goroutines for graceful shutdown
//
// Error handling:
//   - Context canceled: Normal termination, exit loop
//   - Queue closed: Normal termination, exit loop
//   - Handler panics: Recovered to prevent crashing receive loop
func (d *DatagramConn) receiveLoop() {
	for {
		// Peek at next message without consuming
		// We need to check if there's a handler before consuming the message
		select {
		case <-d.ctx.Done():
			return // Context canceled, exit loop
		case msg, ok := <-d.recvQueue:
			if !ok {
				return // Queue closed, exit loop
			}

			// Look up handler for destination port
			d.mu.RLock()
			handler, exists := d.handlers[msg.destPort]
			d.mu.RUnlock()

			if exists && handler != nil {
				// Handler registered - dispatch to it
				d.wg.Add(1)
				go func(h func([]byte, *i2cp.Destination), payload []byte, from *i2cp.Destination) {
					defer d.wg.Done()
					defer func() {
						// Recover from panics in user handlers to prevent crashing receive loop
						if r := recover(); r != nil {
							// Handler panicked - log would go here in production
							// For now, silently recover to keep receive loop running
						}
					}()
					h(payload, from)
				}(handler, msg.payload, msg.from)
			} else {
				// No handler - put message back in queue for manual receive
				// Check if connection is closed first
				d.mu.RLock()
				closed := d.closed
				d.mu.RUnlock()

				if closed {
					return // Connection closed, don't try to send to closed channel
				}

				// Use non-blocking send with context check
				select {
				case d.recvQueue <- msg:
					// Message back in queue
				case <-d.ctx.Done():
					return // Give up if context canceled
				default:
					// Queue full - message is lost
					// This can happen if queue is full and no one is reading
				}
			}
		}
	}
}
