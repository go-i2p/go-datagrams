package datagrams

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	i2cp "github.com/go-i2p/go-i2cp"
)

// fakeAddr is a test type that implements net.Addr but is not an I2PAddr.
// Used for testing type assertion failures in WriteTo.
type fakeAddr struct{}

func (f fakeAddr) Network() string { return "fake" }
func (f fakeAddr) String() string  { return "fake:0" }

// mockSession implements I2CPSession for testing.
// This allows us to test DatagramConn without requiring a real I2P router.
type mockSession struct {
	dest         *i2cp.Destination
	closed       bool
	lastProtocol uint8
	lastSrcPort  uint16
	lastDestPort uint16
	lastPayload  []byte
	sendError    error
}

func (m *mockSession) Destination() *i2cp.Destination {
	return m.dest
}

func (m *mockSession) IsClosed() bool {
	return m.closed
}

func (m *mockSession) SendMessage(destination *i2cp.Destination, protocol uint8, srcPort, destPort uint16, payload *i2cp.Stream, nonce uint32) error {
	if m.sendError != nil {
		return m.sendError
	}
	m.lastProtocol = protocol
	m.lastSrcPort = srcPort
	m.lastDestPort = destPort
	m.lastPayload = payload.Bytes()
	return nil
}

func (m *mockSession) SendMessageWithContext(ctx context.Context, destination *i2cp.Destination, protocol uint8, srcPort, destPort uint16, payload *i2cp.Stream, nonce uint32) error {
	if m.sendError != nil {
		return m.sendError
	}
	m.lastProtocol = protocol
	m.lastSrcPort = srcPort
	m.lastDestPort = destPort
	m.lastPayload = payload.Bytes()
	return nil
}

func (m *mockSession) SigningKeyPair() (*i2cp.Ed25519KeyPair, error) {
	// Return a generated key pair for signing
	crypto := i2cp.NewCrypto()
	return crypto.Ed25519SignatureKeygen()
}

// newMockSession creates a mock I2CP session for testing.
func newMockSession() *mockSession {
	// Create a minimal destination with proper crypto
	crypto := i2cp.NewCrypto()
	dest, _ := i2cp.NewDestination(crypto)
	return &mockSession{
		dest:   dest,
		closed: false,
	}
}

// validDestinationB64 returns a valid base64-encoded I2P destination for testing.
func validDestinationB64() string {
	crypto := i2cp.NewCrypto()
	dest, _ := i2cp.NewDestination(crypto)

	// Use the destination's Base64() method for I2P-compatible encoding
	return dest.Base64()
}

// TestNewDatagramConn verifies basic connection creation.
func TestNewDatagramConn(t *testing.T) {
	session := newMockSession()

	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	if conn.localPort != 8080 {
		t.Errorf("localPort = %d, want 8080", conn.localPort)
	}

	if conn.protocol != ProtocolRaw {
		t.Errorf("protocol = %d, want %d (ProtocolRaw)", conn.protocol, ProtocolRaw)
	}

	if conn.session != session {
		t.Error("session not set correctly")
	}

	if conn.IsClosed() {
		t.Error("new connection should not be closed")
	}
}

// TestNewDatagramConn_NilSession verifies error handling for nil session.
func TestNewDatagramConn_NilSession(t *testing.T) {
	_, err := NewDatagramConn(nil, 8080)
	if err == nil {
		t.Error("NewDatagramConn(nil, 8080) should return error")
	}

	expectedMsg := "session cannot be nil"
	if err.Error() != expectedMsg {
		t.Errorf("error message = %q, want %q", err.Error(), expectedMsg)
	}
}

// TestNewDatagramConn_ClosedSession verifies error handling for closed session.
func TestNewDatagramConn_ClosedSession(t *testing.T) {
	session := newMockSession()
	session.closed = true

	_, err := NewDatagramConn(session, 8080)
	if err == nil {
		t.Error("NewDatagramConn with closed session should return error")
	}

	expectedMsg := "session is closed"
	if err.Error() != expectedMsg {
		t.Errorf("error message = %q, want %q", err.Error(), expectedMsg)
	}
}

// TestNewDatagramConn_NilDestination verifies error handling for session without destination.
func TestNewDatagramConn_NilDestination(t *testing.T) {
	session := &mockSession{
		dest:   nil, // No destination
		closed: false,
	}

	_, err := NewDatagramConn(session, 8080)
	if err == nil {
		t.Error("NewDatagramConn with nil destination should return error")
	}

	expectedMsg := "session has no destination"
	if err.Error() != expectedMsg {
		t.Errorf("error message = %q, want %q", err.Error(), expectedMsg)
	}
}

// TestNewDatagramConnWithProtocol verifies protocol selection.
func TestNewDatagramConnWithProtocol(t *testing.T) {
	tests := []struct {
		name     string
		protocol uint8
		want     uint8
	}{
		{"Raw", ProtocolRaw, ProtocolRaw},
		{"Datagram1", ProtocolDatagram1, ProtocolDatagram1},
		{"Datagram2", ProtocolDatagram2, ProtocolDatagram2},
		{"Datagram3", ProtocolDatagram3, ProtocolDatagram3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := newMockSession()
			conn, err := NewDatagramConnWithProtocol(session, 8080, tt.protocol)
			if err != nil {
				t.Fatalf("NewDatagramConnWithProtocol() failed: %v", err)
			}
			defer conn.Close()

			if conn.protocol != tt.want {
				t.Errorf("protocol = %d, want %d", conn.protocol, tt.want)
			}

			if conn.Protocol() != tt.want {
				t.Errorf("Protocol() = %d, want %d", conn.Protocol(), tt.want)
			}
		})
	}
}

// TestNewDatagramConnWithProtocol_StreamingRejected verifies that protocol 6 (streaming)
// is rejected. Per I2P specification, protocol 6 is reserved for I2P streaming and
// cannot be used for datagrams.
func TestNewDatagramConnWithProtocol_StreamingRejected(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConnWithProtocol(session, 8080, ProtocolStreaming)

	if err == nil {
		conn.Close()
		t.Fatal("NewDatagramConnWithProtocol() should reject protocol 6 (streaming)")
	}

	// Verify error message mentions protocol 6 and streaming
	if !strings.Contains(err.Error(), "6") || !strings.Contains(err.Error(), "streaming") {
		t.Errorf("error message should mention protocol 6 and streaming, got: %v", err)
	}
}

// TestDatagramConn_Close verifies connection close behavior.
func TestDatagramConn_Close(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}

	if conn.IsClosed() {
		t.Error("new connection should not be closed")
	}

	// First close should succeed
	err = conn.Close()
	if err != nil {
		t.Errorf("Close() failed: %v", err)
	}

	if !conn.IsClosed() {
		t.Error("connection should be closed after Close()")
	}

	// Second close should be idempotent (no error)
	err = conn.Close()
	if err != nil {
		t.Errorf("second Close() failed: %v", err)
	}

	// Session should not be closed (DatagramConn doesn't own it)
	if session.IsClosed() {
		t.Error("Close() should not close the underlying session")
	}
}

// TestDatagramConn_LocalAddr verifies LocalAddr implementation.
func TestDatagramConn_LocalAddr(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	addr := conn.LocalAddr()
	if addr == nil {
		t.Fatal("LocalAddr() returned nil")
	}

	// Verify it implements net.Addr
	netAddr, ok := addr.(net.Addr)
	if !ok {
		t.Error("LocalAddr() does not implement net.Addr")
	}

	if netAddr.Network() != "i2p" {
		t.Errorf("Network() = %q, want %q", netAddr.Network(), "i2p")
	}

	// Verify port is correct
	i2pAddr, ok := addr.(*I2PAddr)
	if !ok {
		t.Fatal("LocalAddr() is not *I2PAddr")
	}

	if i2pAddr.Port != 8080 {
		t.Errorf("Port = %d, want 8080", i2pAddr.Port)
	}
}

// TestDatagramConn_SetDeadline verifies deadline setting.
func TestDatagramConn_SetDeadline(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(1 * time.Second)
	err = conn.SetDeadline(deadline)
	if err != nil {
		t.Errorf("SetDeadline() failed: %v", err)
	}

	// Verify both read and write deadlines are set
	if !conn.readDeadline.Equal(deadline) {
		t.Errorf("readDeadline = %v, want %v", conn.readDeadline, deadline)
	}

	if !conn.writeDeadline.Equal(deadline) {
		t.Errorf("writeDeadline = %v, want %v", conn.writeDeadline, deadline)
	}
}

// TestDatagramConn_SetDeadline_Closed verifies deadline setting on closed connection.
func TestDatagramConn_SetDeadline_Closed(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	conn.Close()

	err = conn.SetDeadline(time.Now())
	if err != net.ErrClosed {
		t.Errorf("SetDeadline() on closed conn = %v, want %v", err, net.ErrClosed)
	}
}

// TestDatagramConn_SetReadDeadline verifies read deadline setting.
func TestDatagramConn_SetReadDeadline(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(1 * time.Second)
	err = conn.SetReadDeadline(deadline)
	if err != nil {
		t.Errorf("SetReadDeadline() failed: %v", err)
	}

	if !conn.readDeadline.Equal(deadline) {
		t.Errorf("readDeadline = %v, want %v", conn.readDeadline, deadline)
	}

	// Write deadline should not be affected
	if !conn.writeDeadline.IsZero() {
		t.Errorf("writeDeadline = %v, want zero", conn.writeDeadline)
	}
}

// TestDatagramConn_SetWriteDeadline verifies write deadline setting.
func TestDatagramConn_SetWriteDeadline(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(1 * time.Second)
	err = conn.SetWriteDeadline(deadline)
	if err != nil {
		t.Errorf("SetWriteDeadline() failed: %v", err)
	}

	if !conn.writeDeadline.Equal(deadline) {
		t.Errorf("writeDeadline = %v, want %v", conn.writeDeadline, deadline)
	}

	// Read deadline should not be affected
	if !conn.readDeadline.IsZero() {
		t.Errorf("readDeadline = %v, want zero", conn.readDeadline)
	}
}

// TestDatagramConn_Session verifies Session accessor.
func TestDatagramConn_Session(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	if conn.Session() != session {
		t.Error("Session() did not return the original session")
	}
}

// TestDatagramConn_PortZero verifies that port 0 is allowed.
func TestDatagramConn_PortZero(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 0)
	if err != nil {
		t.Fatalf("NewDatagramConn() with port 0 failed: %v", err)
	}
	defer conn.Close()

	if conn.localPort != 0 {
		t.Errorf("localPort = %d, want 0", conn.localPort)
	}
}

// TestDatagramConn_ConcurrentClose verifies that Close is safe for concurrent calls.
func TestDatagramConn_ConcurrentClose(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}

	// Close concurrently from multiple goroutines
	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			conn.Close()
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Connection should be closed
	if !conn.IsClosed() {
		t.Error("connection should be closed after concurrent Close() calls")
	}
}

// TestDatagramConn_DeadlineOperations verifies deadline operations don't panic.
func TestDatagramConn_DeadlineOperations(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Test setting to zero (no deadline)
	err = conn.SetDeadline(time.Time{})
	if err != nil {
		t.Errorf("SetDeadline(zero) failed: %v", err)
	}

	// Test setting to past time
	err = conn.SetDeadline(time.Now().Add(-1 * time.Hour))
	if err != nil {
		t.Errorf("SetDeadline(past) failed: %v", err)
	}

	// Test setting to future time
	err = conn.SetDeadline(time.Now().Add(1 * time.Hour))
	if err != nil {
		t.Errorf("SetDeadline(future) failed: %v", err)
	}
}

// TestDatagramConn_PacketConnInterface verifies DatagramConn implements net.PacketConn.
// This is a compile-time check.
func TestDatagramConn_PacketConnInterface(t *testing.T) {
	// This will fail to compile if DatagramConn doesn't implement net.PacketConn
	// Note: We can't fully implement the interface yet (ReadFrom/WriteTo not implemented),
	// but we can verify the methods we have implemented so far.
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Verify methods that should exist
	_ = conn.LocalAddr()
	_ = conn.SetDeadline(time.Now())
	_ = conn.SetReadDeadline(time.Now())
	_ = conn.SetWriteDeadline(time.Now())
	_ = conn.Close()
}

// BenchmarkNewDatagramConn benchmarks connection creation.
func BenchmarkNewDatagramConn(b *testing.B) {
	session := newMockSession()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, _ := NewDatagramConn(session, 8080)
		conn.Close()
	}
}

// BenchmarkDatagramConn_Close benchmarks Close operation.
func BenchmarkDatagramConn_Close(b *testing.B) {
	session := newMockSession()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		conn, _ := NewDatagramConn(session, 8080)
		b.StartTimer()
		conn.Close()
	}
}

// TestSendTo_Raw tests sending Raw protocol datagrams.
func TestSendTo_Raw(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	payload := []byte("test payload")
	destStr := validDestinationB64()

	err = conn.SendTo(payload, destStr, 9090)
	if err != nil {
		t.Fatalf("SendTo() failed: %v", err)
	}

	// Verify protocol
	if session.lastProtocol != ProtocolRaw {
		t.Errorf("protocol = %d, want %d", session.lastProtocol, ProtocolRaw)
	}

	// Verify ports
	if session.lastSrcPort != 8080 {
		t.Errorf("srcPort = %d, want 8080", session.lastSrcPort)
	}
	if session.lastDestPort != 9090 {
		t.Errorf("destPort = %d, want 9090", session.lastDestPort)
	}

	// Raw protocol should send payload directly (no envelope)
	if string(session.lastPayload) != string(payload) {
		t.Errorf("payload = %q, want %q", session.lastPayload, payload)
	}
}

// TestSendTo_Datagram3 tests sending Datagram3 protocol datagrams.
func TestSendTo_Datagram3(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConnWithProtocol(session, 8080, ProtocolDatagram3)
	if err != nil {
		t.Fatalf("NewDatagramConnWithProtocol() failed: %v", err)
	}
	defer conn.Close()

	payload := []byte("test payload")
	destStr := validDestinationB64()

	err = conn.SendTo(payload, destStr, 9090)
	if err != nil {
		t.Fatalf("SendTo() failed: %v", err)
	}

	// Verify protocol
	if session.lastProtocol != ProtocolDatagram3 {
		t.Errorf("protocol = %d, want %d", session.lastProtocol, ProtocolDatagram3)
	}

	// Datagram3 envelope: fromhash(32) + flags(2) + payload
	if len(session.lastPayload) != 32+2+len(payload) {
		t.Errorf("envelope size = %d, want %d", len(session.lastPayload), 32+2+len(payload))
	}

	// Verify flags: version 0x03 (bits 3-0), no options (bit 4 = 0)
	if session.lastPayload[32] != 0x00 || session.lastPayload[33] != 0x03 {
		t.Errorf("flags = [%02x %02x], want [00 03]", session.lastPayload[32], session.lastPayload[33])
	}

	// Verify payload is at the end
	envelopePayload := session.lastPayload[34:]
	if string(envelopePayload) != string(payload) {
		t.Errorf("envelope payload = %q, want %q", envelopePayload, payload)
	}
}

// TestSendTo_ClosedConnection tests sending on a closed connection.
func TestSendTo_ClosedConnection(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}

	conn.Close()

	err = conn.SendTo([]byte("test"), "dest", 9090)
	if err != net.ErrClosed {
		t.Errorf("SendTo() on closed connection error = %v, want %v", err, net.ErrClosed)
	}
}

// TestSendTo_PayloadTooLarge tests size validation.
func TestSendTo_PayloadTooLarge(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Create payload larger than MaxI2NPSize
	largePayload := make([]byte, MaxI2NPSize+1)

	err = conn.SendTo(largePayload, "dest", 9090)
	if err == nil {
		t.Error("SendTo() with oversized payload should return error")
	}

	if err != nil && err.Error()[:12] != "payload size" {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestSendTo_WriteDeadline tests write deadline handling.
func TestSendTo_WriteDeadline(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Set deadline in the past
	conn.SetWriteDeadline(time.Now().Add(-1 * time.Second))

	err = conn.SendTo([]byte("test"), "dest", 9090)
	if err == nil {
		t.Error("SendTo() after deadline should return error")
	}

	if err != nil && err.Error()[:14] != "write deadline" {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestSendTo_InvalidDestination tests error handling for invalid destinations.
func TestSendTo_InvalidDestination(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Empty destination should fail
	err = conn.SendTo([]byte("test"), "", 9090)
	if err == nil {
		t.Error("SendTo() with empty destination should return error")
	}
}

// TestSendTo_Datagram1 tests that Datagram1 sends correctly with envelope and signature.
func TestSendTo_Datagram1(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConnWithProtocol(session, 8080, ProtocolDatagram1)
	if err != nil {
		t.Fatalf("NewDatagramConnWithProtocol() failed: %v", err)
	}
	defer conn.Close()

	testPayload := []byte("test")
	err = conn.SendTo(testPayload, validDestinationB64(), 9090)
	if err != nil {
		t.Fatalf("SendTo() with Datagram1 should succeed: %v", err)
	}

	// Verify the envelope was built correctly:
	// Format: dest(391 bytes) + signature(64 bytes) + payload
	expectedMinSize := 391 + Ed25519SignatureLength + len(testPayload)
	if len(session.lastPayload) < expectedMinSize {
		t.Errorf("envelope too small: got %d bytes, want at least %d", len(session.lastPayload), expectedMinSize)
	}

	// Verify the protocol was set correctly
	if session.lastProtocol != ProtocolDatagram1 {
		t.Errorf("protocol = %d, want %d", session.lastProtocol, ProtocolDatagram1)
	}
}

// TestSendTo_Datagram2 tests that Datagram2 sends correctly with envelope and signature.
func TestSendTo_Datagram2(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConnWithProtocol(session, 8080, ProtocolDatagram2)
	if err != nil {
		t.Fatalf("NewDatagramConnWithProtocol() failed: %v", err)
	}
	defer conn.Close()

	testPayload := []byte("test")
	err = conn.SendTo(testPayload, validDestinationB64(), 9090)
	if err != nil {
		t.Fatalf("SendTo() with Datagram2 should succeed: %v", err)
	}

	// Verify the envelope was built correctly:
	// Format: dest(391 bytes) + flags(2 bytes) + payload + signature(64 bytes)
	expectedMinSize := 391 + 2 + len(testPayload) + Ed25519SignatureLength
	if len(session.lastPayload) < expectedMinSize {
		t.Errorf("envelope too small: got %d bytes, want at least %d", len(session.lastPayload), expectedMinSize)
	}

	// Verify the protocol was set correctly
	if session.lastProtocol != ProtocolDatagram2 {
		t.Errorf("protocol = %d, want %d", session.lastProtocol, ProtocolDatagram2)
	}
}

// TestMaxPayloadSize tests the MaxPayloadSize calculation for each protocol.
func TestMaxPayloadSize(t *testing.T) {
	session := newMockSession()

	tests := []struct {
		name     string
		protocol uint8
		want     int
	}{
		{"Raw", ProtocolRaw, MaxI2NPSize},
		{"Datagram3", ProtocolDatagram3, MaxI2NPSize - Datagram3Overhead},
		{"Datagram1", ProtocolDatagram1, MaxI2NPSize - Datagram1Overhead},
		{"Datagram2", ProtocolDatagram2, MaxI2NPSize - Datagram2Overhead},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := NewDatagramConnWithProtocol(session, 8080, tt.protocol)
			if err != nil {
				t.Fatalf("NewDatagramConnWithProtocol() failed: %v", err)
			}
			defer conn.Close()

			got := conn.MaxPayloadSize()
			if got != tt.want {
				t.Errorf("MaxPayloadSize() = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestReceiveFrom_Raw tests receiving Raw protocol datagrams.
func TestReceiveFrom_Raw(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Create a test destination
	crypto := i2cp.NewCrypto()
	fromDest, _ := i2cp.NewDestination(crypto)

	// Inject a message
	payload := []byte("test message")
	err = conn.injectMessage(payload, fromDest, ProtocolRaw, 9090, 8080)
	if err != nil {
		t.Fatalf("injectMessage() failed: %v", err)
	}

	// Receive the message
	receivedPayload, receivedFrom, receivedPort, err := conn.ReceiveFrom()
	if err != nil {
		t.Fatalf("ReceiveFrom() failed: %v", err)
	}

	// Verify payload
	if string(receivedPayload) != string(payload) {
		t.Errorf("payload = %q, want %q", receivedPayload, payload)
	}

	// Verify sender
	if receivedFrom != fromDest {
		t.Error("sender destination mismatch")
	}

	// Verify port
	if receivedPort != 9090 {
		t.Errorf("srcPort = %d, want 9090", receivedPort)
	}
}

// TestReceiveFrom_Datagram3 tests receiving Datagram3 protocol datagrams.
func TestReceiveFrom_Datagram3(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConnWithProtocol(session, 8080, ProtocolDatagram3)
	if err != nil {
		t.Fatalf("NewDatagramConnWithProtocol() failed: %v", err)
	}
	defer conn.Close()

	// Create a test destination
	crypto := i2cp.NewCrypto()
	fromDest, _ := i2cp.NewDestination(crypto)

	// Construct Datagram3 envelope: fromhash(32) + flags(2) + payload
	payload := []byte("test message")
	destStream := i2cp.NewStream(nil)
	fromDest.WriteToStream(destStream)
	fromHash := sha256.Sum256(destStream.Bytes())

	envelope := make([]byte, 32+2+len(payload))
	copy(envelope[0:32], fromHash[:])
	envelope[32] = 0x00 // flags high byte
	envelope[33] = 0x03 // flags low byte (version 0x03)
	copy(envelope[34:], payload)

	// Inject the message with envelope
	err = conn.injectMessage(envelope, fromDest, ProtocolDatagram3, 9090, 8080)
	if err != nil {
		t.Fatalf("injectMessage() failed: %v", err)
	}

	// Receive the message
	receivedPayload, _, receivedPort, err := conn.ReceiveFrom()
	if err != nil {
		t.Fatalf("ReceiveFrom() failed: %v", err)
	}

	// Verify payload was extracted correctly
	if string(receivedPayload) != string(payload) {
		t.Errorf("payload = %q, want %q", receivedPayload, payload)
	}

	// Verify port
	if receivedPort != 9090 {
		t.Errorf("srcPort = %d, want 9090", receivedPort)
	}
}

// TestReceiveFrom_ClosedConnection tests receiving on a closed connection.
func TestReceiveFrom_ClosedConnection(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}

	conn.Close()

	_, _, _, err = conn.ReceiveFrom()
	if err != net.ErrClosed {
		t.Errorf("ReceiveFrom() on closed connection error = %v, want %v", err, net.ErrClosed)
	}
}

// TestReceiveFrom_ReadDeadline tests read deadline handling.
func TestReceiveFrom_ReadDeadline(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Set deadline in the past
	conn.SetReadDeadline(time.Now().Add(-1 * time.Second))

	_, _, _, err = conn.ReceiveFrom()
	if err == nil {
		t.Error("ReceiveFrom() after deadline should return error")
	}

	if err != nil && err.Error()[:13] != "read deadline" {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestReceiveFrom_Datagram3MalformedEnvelope tests error handling for malformed Datagram3.
func TestReceiveFrom_Datagram3MalformedEnvelope(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConnWithProtocol(session, 8080, ProtocolDatagram3)
	if err != nil {
		t.Fatalf("NewDatagramConnWithProtocol() failed: %v", err)
	}
	defer conn.Close()

	// Create a test destination
	crypto := i2cp.NewCrypto()
	fromDest, _ := i2cp.NewDestination(crypto)

	// Inject a message with envelope too short (only 20 bytes)
	shortEnvelope := make([]byte, 20)
	err = conn.injectMessage(shortEnvelope, fromDest, ProtocolDatagram3, 9090, 8080)
	if err != nil {
		t.Fatalf("injectMessage() failed: %v", err)
	}

	// Receive should fail with parse error
	_, _, _, err = conn.ReceiveFrom()
	if err == nil {
		t.Error("ReceiveFrom() with malformed envelope should return error")
	}

	if err != nil && err.Error()[:9] != "Datagram3" {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestReceiveFrom_Datagram3InvalidVersion tests version validation.
func TestReceiveFrom_Datagram3InvalidVersion(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConnWithProtocol(session, 8080, ProtocolDatagram3)
	if err != nil {
		t.Fatalf("NewDatagramConnWithProtocol() failed: %v", err)
	}
	defer conn.Close()

	// Create a test destination
	crypto := i2cp.NewCrypto()
	fromDest, _ := i2cp.NewDestination(crypto)

	// Construct envelope with wrong version (0x02 instead of 0x03)
	payload := []byte("test")
	envelope := make([]byte, 32+2+len(payload))
	envelope[32] = 0x00
	envelope[33] = 0x02 // Wrong version
	copy(envelope[34:], payload)

	err = conn.injectMessage(envelope, fromDest, ProtocolDatagram3, 9090, 8080)
	if err != nil {
		t.Fatalf("injectMessage() failed: %v", err)
	}

	// Receive should fail with version error
	_, _, _, err = conn.ReceiveFrom()
	if err == nil {
		t.Error("ReceiveFrom() with invalid version should return error")
	}

	if err != nil && err.Error()[:7] != "invalid" {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestReceiveFrom_Datagram1MalformedEnvelope tests error handling for truncated Datagram1 envelope.
func TestReceiveFrom_Datagram1MalformedEnvelope(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConnWithProtocol(session, 8080, ProtocolDatagram1)
	if err != nil {
		t.Fatalf("NewDatagramConnWithProtocol() failed: %v", err)
	}
	defer conn.Close()

	// Create a test destination
	crypto := i2cp.NewCrypto()
	fromDest, _ := i2cp.NewDestination(crypto)

	// Inject envelope too short (less than minSize of 391+64=455 bytes)
	shortEnvelope := make([]byte, 100)
	err = conn.injectMessage(shortEnvelope, fromDest, ProtocolDatagram1, 9090, 8080)
	if err != nil {
		t.Fatalf("injectMessage() failed: %v", err)
	}

	// Receive should fail with parse error
	_, _, _, err = conn.ReceiveFrom()
	if err == nil {
		t.Error("ReceiveFrom() with malformed Datagram1 envelope should return error")
	}

	if err != nil && !strings.Contains(err.Error(), "too short") {
		t.Errorf("unexpected error message (should mention too short): %v", err)
	}
}

// TestReceiveFrom_Datagram1InvalidSignature tests error handling for invalid Datagram1 signature.
func TestReceiveFrom_Datagram1InvalidSignature(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConnWithProtocol(session, 8080, ProtocolDatagram1)
	if err != nil {
		t.Fatalf("NewDatagramConnWithProtocol() failed: %v", err)
	}
	defer conn.Close()

	// Create a test destination and serialize it
	crypto := i2cp.NewCrypto()
	fromDest, _ := i2cp.NewDestination(crypto)

	// Build envelope with valid destination but corrupted signature
	destStream := i2cp.NewStream(nil)
	if err := fromDest.WriteToMessage(destStream); err != nil {
		t.Fatalf("WriteToMessage() failed: %v", err)
	}
	destBytes := destStream.Bytes()

	// Create envelope: dest (391 bytes) + garbage signature (64 bytes) + payload
	payload := []byte("test payload")
	envelope := make([]byte, len(destBytes)+Ed25519SignatureLength+len(payload))
	copy(envelope[:len(destBytes)], destBytes)
	// Leave signature as zeros (invalid)
	copy(envelope[len(destBytes)+Ed25519SignatureLength:], payload)

	err = conn.injectMessage(envelope, fromDest, ProtocolDatagram1, 9090, 8080)
	if err != nil {
		t.Fatalf("injectMessage() failed: %v", err)
	}

	// Receive should fail with signature verification error
	_, _, _, err = conn.ReceiveFrom()
	if err == nil {
		t.Error("ReceiveFrom() with invalid Datagram1 signature should return error")
	}

	if err != nil && !strings.Contains(err.Error(), "signature") {
		t.Errorf("unexpected error message (should mention signature): %v", err)
	}
}

// TestReceiveFrom_Datagram2MalformedEnvelope tests error handling for truncated Datagram2 envelope.
func TestReceiveFrom_Datagram2MalformedEnvelope(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConnWithProtocol(session, 8080, ProtocolDatagram2)
	if err != nil {
		t.Fatalf("NewDatagramConnWithProtocol() failed: %v", err)
	}
	defer conn.Close()

	// Create a test destination
	crypto := i2cp.NewCrypto()
	fromDest, _ := i2cp.NewDestination(crypto)

	// Inject envelope too short (less than minSize of 391+2+64=457 bytes)
	shortEnvelope := make([]byte, 100)
	err = conn.injectMessage(shortEnvelope, fromDest, ProtocolDatagram2, 9090, 8080)
	if err != nil {
		t.Fatalf("injectMessage() failed: %v", err)
	}

	// Receive should fail with parse error
	_, _, _, err = conn.ReceiveFrom()
	if err == nil {
		t.Error("ReceiveFrom() with malformed Datagram2 envelope should return error")
	}

	if err != nil && !strings.Contains(err.Error(), "too short") {
		t.Errorf("unexpected error message (should mention too short): %v", err)
	}
}

// TestReceiveFrom_Datagram2InvalidSignature tests error handling for invalid Datagram2 signature.
func TestReceiveFrom_Datagram2InvalidSignature(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConnWithProtocol(session, 8080, ProtocolDatagram2)
	if err != nil {
		t.Fatalf("NewDatagramConnWithProtocol() failed: %v", err)
	}
	defer conn.Close()

	// Create a test destination and serialize it
	crypto := i2cp.NewCrypto()
	fromDest, _ := i2cp.NewDestination(crypto)

	// Build envelope with valid destination but corrupted signature
	destStream := i2cp.NewStream(nil)
	if err := fromDest.WriteToMessage(destStream); err != nil {
		t.Fatalf("WriteToMessage() failed: %v", err)
	}
	destBytes := destStream.Bytes()

	// Create envelope: dest (391 bytes) + flags (2 bytes) + payload + garbage signature (64 bytes)
	payload := []byte("test payload")
	envelope := make([]byte, len(destBytes)+2+len(payload)+Ed25519SignatureLength)
	copy(envelope[:len(destBytes)], destBytes)
	// Set flags to 0x0002 (version 2 for Datagram2)
	envelope[len(destBytes)] = 0x00
	envelope[len(destBytes)+1] = 0x02
	copy(envelope[len(destBytes)+2:len(destBytes)+2+len(payload)], payload)
	// Leave signature as zeros at the end (invalid)

	err = conn.injectMessage(envelope, fromDest, ProtocolDatagram2, 9090, 8080)
	if err != nil {
		t.Fatalf("injectMessage() failed: %v", err)
	}

	// Receive should fail with signature verification error
	_, _, _, err = conn.ReceiveFrom()
	if err == nil {
		t.Error("ReceiveFrom() with invalid Datagram2 signature should return error")
	}

	if err != nil && !strings.Contains(err.Error(), "signature") {
		t.Errorf("unexpected error message (should mention signature): %v", err)
	}
}

// TestReceiveFrom_QueueFull tests behavior when receive queue is full.
func TestReceiveFrom_QueueFull(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Create a test destination
	crypto := i2cp.NewCrypto()
	fromDest, _ := i2cp.NewDestination(crypto)

	// Fill the queue (buffer is 100)
	for i := 0; i < 100; i++ {
		err := conn.injectMessage([]byte("test"), fromDest, ProtocolRaw, 9090, 8080)
		if err != nil {
			t.Fatalf("injectMessage() %d failed: %v", i, err)
		}
	}

	// Next inject should fail
	err = conn.injectMessage([]byte("test"), fromDest, ProtocolRaw, 9090, 8080)
	if err == nil {
		t.Error("injectMessage() on full queue should return error")
	}

	if err != nil && err.Error() != "receive queue full" {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestReadFrom_Raw tests ReadFrom with Raw protocol.
func TestReadFrom_Raw(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Create a test destination
	crypto := i2cp.NewCrypto()
	fromDest, _ := i2cp.NewDestination(crypto)

	// Inject a Raw datagram
	testPayload := []byte("Hello, I2P!")
	err = conn.injectMessage(testPayload, fromDest, ProtocolRaw, 9090, 8080)
	if err != nil {
		t.Fatalf("injectMessage() failed: %v", err)
	}

	// Read using ReadFrom
	buf := make([]byte, 1024)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom() failed: %v", err)
	}

	// Check bytes read
	if n != len(testPayload) {
		t.Errorf("ReadFrom() returned %d bytes, want %d", n, len(testPayload))
	}

	// Check payload matches
	if string(buf[:n]) != string(testPayload) {
		t.Errorf("ReadFrom() payload = %q, want %q", string(buf[:n]), string(testPayload))
	}

	// Check address type
	i2pAddr, ok := addr.(*I2PAddr)
	if !ok {
		t.Fatalf("ReadFrom() address type = %T, want *I2PAddr", addr)
	}

	// Check port
	if i2pAddr.Port != 9090 {
		t.Errorf("ReadFrom() address port = %d, want 9090", i2pAddr.Port)
	}
}

// TestReadFrom_Datagram3 tests ReadFrom with Datagram3 protocol.
func TestReadFrom_Datagram3(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConnWithProtocol(session, 8080, ProtocolDatagram3)
	if err != nil {
		t.Fatalf("NewDatagramConnWithProtocol() failed: %v", err)
	}
	defer conn.Close()

	// Create a test destination
	crypto := i2cp.NewCrypto()
	fromDest, _ := i2cp.NewDestination(crypto)

	// Construct a Datagram3 envelope: fromhash(32) + flags(2) + payload
	testPayload := []byte("Hello, Datagram3!")

	// Compute fromhash
	destStream := i2cp.NewStream(nil)
	fromDest.WriteToStream(destStream)
	fromHash := sha256.Sum256(destStream.Bytes())

	// Build envelope
	envelope := make([]byte, 32+2+len(testPayload))
	copy(envelope[0:32], fromHash[:])
	envelope[32] = 0x00 // flags high byte
	envelope[33] = 0x03 // flags low byte (version 0x03)
	copy(envelope[34:], testPayload)

	// Inject the Datagram3 message
	err = conn.injectMessage(envelope, fromDest, ProtocolDatagram3, 9090, 8080)
	if err != nil {
		t.Fatalf("injectMessage() failed: %v", err)
	}

	// Read using ReadFrom
	buf := make([]byte, 1024)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom() failed: %v", err)
	}

	// Check bytes read (should be payload only, not envelope)
	if n != len(testPayload) {
		t.Errorf("ReadFrom() returned %d bytes, want %d", n, len(testPayload))
	}

	// Check payload matches (envelope should be stripped)
	if string(buf[:n]) != string(testPayload) {
		t.Errorf("ReadFrom() payload = %q, want %q", string(buf[:n]), string(testPayload))
	}

	// Check address type
	i2pAddr, ok := addr.(*I2PAddr)
	if !ok {
		t.Fatalf("ReadFrom() address type = %T, want *I2PAddr", addr)
	}

	// Check port
	if i2pAddr.Port != 9090 {
		t.Errorf("ReadFrom() address port = %d, want 9090", i2pAddr.Port)
	}
}

// TestReadFrom_ShortBuffer tests ReadFrom with a buffer that's too small.
func TestReadFrom_ShortBuffer(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Create a test destination
	crypto := i2cp.NewCrypto()
	fromDest, _ := i2cp.NewDestination(crypto)

	// Inject a message larger than our buffer
	testPayload := []byte("This is a long message that will be truncated")
	err = conn.injectMessage(testPayload, fromDest, ProtocolRaw, 9090, 8080)
	if err != nil {
		t.Fatalf("injectMessage() failed: %v", err)
	}

	// Read with small buffer
	buf := make([]byte, 10)
	n, addr, err := conn.ReadFrom(buf)

	// Should not return error (matches net.UDPConn behavior)
	if err != nil {
		t.Errorf("ReadFrom() with short buffer returned error: %v", err)
	}

	// Check bytes read equals buffer size
	if n != len(buf) {
		t.Errorf("ReadFrom() returned %d bytes, want %d", n, len(buf))
	}

	// Check we got the first part of the payload
	if string(buf[:n]) != string(testPayload[:10]) {
		t.Errorf("ReadFrom() payload = %q, want %q", string(buf[:n]), string(testPayload[:10]))
	}

	// Address should still be valid
	if addr == nil {
		t.Error("ReadFrom() returned nil address")
	}
}

// TestReadFrom_ClosedConnection tests ReadFrom on a closed connection.
func TestReadFrom_ClosedConnection(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}

	// Close the connection
	conn.Close()

	// Try to read
	buf := make([]byte, 1024)
	_, _, err = conn.ReadFrom(buf)
	if err != net.ErrClosed {
		t.Errorf("ReadFrom() on closed connection = %v, want net.ErrClosed", err)
	}
}

// TestReadFrom_ReadDeadline tests ReadFrom with a read deadline.
func TestReadFrom_ReadDeadline(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Set a deadline in the past
	conn.SetReadDeadline(time.Now().Add(-1 * time.Second))

	// Try to read
	buf := make([]byte, 1024)
	_, _, err = conn.ReadFrom(buf)
	if err == nil {
		t.Error("ReadFrom() with expired deadline should return error")
	}

	if err != nil && err.Error() != "read deadline exceeded" {
		t.Errorf("ReadFrom() error = %v, want 'read deadline exceeded'", err)
	}
}

// TestReadFrom_AddressFormat tests that ReadFrom returns proper I2PAddr.
func TestReadFrom_AddressFormat(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Create a test destination
	crypto := i2cp.NewCrypto()
	fromDest, _ := i2cp.NewDestination(crypto)

	// Inject a message
	err = conn.injectMessage([]byte("test"), fromDest, ProtocolRaw, 12345, 8080)
	if err != nil {
		t.Fatalf("injectMessage() failed: %v", err)
	}

	// Read using ReadFrom
	buf := make([]byte, 1024)
	_, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom() failed: %v", err)
	}

	// Check Network() method
	if addr.Network() != "i2p" {
		t.Errorf("addr.Network() = %q, want 'i2p'", addr.Network())
	}

	// Check String() method returns something
	addrStr := addr.String()
	if addrStr == "" {
		t.Error("addr.String() returned empty string")
	}

	// Verify it's an I2PAddr
	i2pAddr, ok := addr.(*I2PAddr)
	if !ok {
		t.Fatalf("addr type = %T, want *I2PAddr", addr)
	}

	// Verify port is correct
	if i2pAddr.Port != 12345 {
		t.Errorf("i2pAddr.Port = %d, want 12345", i2pAddr.Port)
	}
}

// TestReadFrom_MultipleReads tests multiple sequential reads.
func TestReadFrom_MultipleReads(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Create a test destination
	crypto := i2cp.NewCrypto()
	fromDest, _ := i2cp.NewDestination(crypto)

	// Inject multiple messages
	messages := []string{"first", "second", "third"}
	for _, msg := range messages {
		err = conn.injectMessage([]byte(msg), fromDest, ProtocolRaw, 9090, 8080)
		if err != nil {
			t.Fatalf("injectMessage() failed: %v", err)
		}
	}

	// Read all messages
	buf := make([]byte, 1024)
	for i, expected := range messages {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom() %d failed: %v", i, err)
		}

		got := string(buf[:n])
		if got != expected {
			t.Errorf("ReadFrom() %d = %q, want %q", i, got, expected)
		}
	}
}

// TestWriteTo_Raw tests WriteTo with Raw protocol.
func TestWriteTo_Raw(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Create a test address
	testPayload := []byte("Hello, WriteTo!")
	destAddr := &I2PAddr{
		Destination: validDestinationB64(),
		Port:        9090,
	}

	// Write using WriteTo
	n, err := conn.WriteTo(testPayload, destAddr)
	if err != nil {
		t.Fatalf("WriteTo() failed: %v", err)
	}

	// Check bytes written
	if n != len(testPayload) {
		t.Errorf("WriteTo() returned %d bytes, want %d", n, len(testPayload))
	}

	// Verify the mock session received the message
	if session.lastDestPort != 9090 {
		t.Errorf("WriteTo() sent to port %d, want 9090", session.lastDestPort)
	}

	if session.lastSrcPort != 8080 {
		t.Errorf("WriteTo() sent from port %d, want 8080", session.lastSrcPort)
	}

	// For Raw protocol, payload should be sent directly
	if string(session.lastPayload) != string(testPayload) {
		t.Errorf("WriteTo() payload = %q, want %q", string(session.lastPayload), string(testPayload))
	}
}

// TestWriteTo_Datagram3 tests WriteTo with Datagram3 protocol.
func TestWriteTo_Datagram3(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConnWithProtocol(session, 8080, ProtocolDatagram3)
	if err != nil {
		t.Fatalf("NewDatagramConnWithProtocol() failed: %v", err)
	}
	defer conn.Close()

	// Create a test address
	testPayload := []byte("Hello, Datagram3!")
	destAddr := &I2PAddr{
		Destination: validDestinationB64(),
		Port:        9090,
	}

	// Write using WriteTo
	n, err := conn.WriteTo(testPayload, destAddr)
	if err != nil {
		t.Fatalf("WriteTo() failed: %v", err)
	}

	// Check bytes written (should be payload length, not envelope length)
	if n != len(testPayload) {
		t.Errorf("WriteTo() returned %d bytes, want %d", n, len(testPayload))
	}

	// Verify Datagram3 envelope was constructed (fromhash + flags + payload)
	if len(session.lastPayload) != 34+len(testPayload) {
		t.Errorf("WriteTo() envelope length = %d, want %d", len(session.lastPayload), 34+len(testPayload))
	}

	// Verify payload is at the end of the envelope
	envelopePayload := session.lastPayload[34:]
	if string(envelopePayload) != string(testPayload) {
		t.Errorf("WriteTo() envelope payload = %q, want %q", string(envelopePayload), string(testPayload))
	}
}

// TestWriteTo_InvalidAddressType tests WriteTo with wrong address type.
func TestWriteTo_InvalidAddressType(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Try to write with a non-I2PAddr address (but still net.Addr)
	addr := fakeAddr{}

	_, err = conn.WriteTo([]byte("test"), addr)
	if err == nil {
		t.Error("WriteTo() with invalid address type should return error")
	}

	// Error should mention type mismatch
	if err != nil && err.Error()[:17] != "address must be *" {
		t.Errorf("WriteTo() error = %v, want type assertion error", err)
	}
}

// TestWriteTo_EmptyDestination tests WriteTo with empty destination.
func TestWriteTo_EmptyDestination(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Create an address with empty destination
	addr := &I2PAddr{
		Destination: "",
		Port:        9090,
	}

	_, err = conn.WriteTo([]byte("test"), addr)
	if err == nil {
		t.Error("WriteTo() with empty destination should return error")
	}

	if err != nil && err.Error() != "destination address is empty" {
		t.Errorf("WriteTo() error = %v, want 'destination address is empty'", err)
	}
}

// TestWriteTo_ClosedConnection tests WriteTo on a closed connection.
func TestWriteTo_ClosedConnection(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}

	// Close the connection
	conn.Close()

	// Try to write
	addr := &I2PAddr{
		Destination: validDestinationB64(),
		Port:        9090,
	}

	_, err = conn.WriteTo([]byte("test"), addr)
	if err != net.ErrClosed {
		t.Errorf("WriteTo() on closed connection = %v, want net.ErrClosed", err)
	}
}

// TestWriteTo_WriteDeadline tests WriteTo with a write deadline.
func TestWriteTo_WriteDeadline(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Set a deadline in the past
	conn.SetWriteDeadline(time.Now().Add(-1 * time.Second))

	// Try to write
	addr := &I2PAddr{
		Destination: validDestinationB64(),
		Port:        9090,
	}

	_, err = conn.WriteTo([]byte("test"), addr)
	if err == nil {
		t.Error("WriteTo() with expired deadline should return error")
	}

	if err != nil && err.Error() != "write deadline exceeded" {
		t.Errorf("WriteTo() error = %v, want 'write deadline exceeded'", err)
	}
}

// TestWriteTo_PayloadTooLarge tests WriteTo with oversized payload.
func TestWriteTo_PayloadTooLarge(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Create a payload larger than max size
	maxSize := conn.MaxPayloadSize()
	largePayload := make([]byte, maxSize+1)

	addr := &I2PAddr{
		Destination: validDestinationB64(),
		Port:        9090,
	}

	_, err = conn.WriteTo(largePayload, addr)
	if err == nil {
		t.Error("WriteTo() with oversized payload should return error")
	}

	if err != nil && err.Error()[:13] != "payload size " {
		t.Errorf("WriteTo() error = %v, want payload size error", err)
	}
}

// TestWriteTo_MultipleWrites tests multiple sequential writes.
func TestWriteTo_MultipleWrites(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	addr := &I2PAddr{
		Destination: validDestinationB64(),
		Port:        9090,
	}

	// Write multiple messages
	messages := []string{"first", "second", "third"}
	for i, msg := range messages {
		n, err := conn.WriteTo([]byte(msg), addr)
		if err != nil {
			t.Fatalf("WriteTo() %d failed: %v", i, err)
		}

		if n != len(msg) {
			t.Errorf("WriteTo() %d returned %d bytes, want %d", i, n, len(msg))
		}

		// Verify the last message sent matches
		if string(session.lastPayload) != msg {
			t.Errorf("WriteTo() %d payload = %q, want %q", i, string(session.lastPayload), msg)
		}
	}
}

// TestWriteTo_AddressInterface tests that WriteTo accepts net.Addr interface.
func TestWriteTo_AddressInterface(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Create an I2PAddr
	i2pAddr := &I2PAddr{
		Destination: validDestinationB64(),
		Port:        9090,
	}

	// Convert to net.Addr interface
	var addr net.Addr = i2pAddr

	// Should work with interface type
	n, err := conn.WriteTo([]byte("test"), addr)
	if err != nil {
		t.Fatalf("WriteTo() with net.Addr interface failed: %v", err)
	}

	if n != 4 {
		t.Errorf("WriteTo() returned %d bytes, want 4", n)
	}
}

// TestRegisterPort_Success tests successful port registration.
func TestRegisterPort_Success(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Register a handler
	handler := func(payload []byte, from *i2cp.Destination) {}

	err = conn.RegisterPort(9090, handler)
	if err != nil {
		t.Fatalf("RegisterPort() failed: %v", err)
	}

	// Verify handler was registered
	conn.mu.RLock()
	_, exists := conn.handlers[9090]
	conn.mu.RUnlock()

	if !exists {
		t.Error("RegisterPort() did not register handler")
	}
}

// TestRegisterPort_DuplicatePort tests registering same port twice.
func TestRegisterPort_DuplicatePort(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Register first handler
	handler1 := func(payload []byte, from *i2cp.Destination) {}
	err = conn.RegisterPort(9090, handler1)
	if err != nil {
		t.Fatalf("RegisterPort() first call failed: %v", err)
	}

	// Try to register same port again
	handler2 := func(payload []byte, from *i2cp.Destination) {}
	err = conn.RegisterPort(9090, handler2)
	if err == nil {
		t.Error("RegisterPort() with duplicate port should return error")
	}

	if err != nil && err.Error() != "port 9090 already registered" {
		t.Errorf("RegisterPort() error = %v, want 'port 9090 already registered'", err)
	}
}

// TestRegisterPort_NilHandler tests registering with nil handler.
func TestRegisterPort_NilHandler(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Try to register nil handler
	err = conn.RegisterPort(9090, nil)
	if err == nil {
		t.Error("RegisterPort() with nil handler should return error")
	}

	if err != nil && err.Error() != "handler cannot be nil" {
		t.Errorf("RegisterPort() error = %v, want 'handler cannot be nil'", err)
	}
}

// TestRegisterPort_ClosedConnection tests registering on closed connection.
func TestRegisterPort_ClosedConnection(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}

	// Close the connection
	conn.Close()

	// Try to register handler
	handler := func(payload []byte, from *i2cp.Destination) {}
	err = conn.RegisterPort(9090, handler)
	if err != net.ErrClosed {
		t.Errorf("RegisterPort() on closed connection = %v, want net.ErrClosed", err)
	}
}

// TestRegisterPort_MultiplePorts tests registering multiple different ports.
func TestRegisterPort_MultiplePorts(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Register multiple handlers
	ports := []uint16{9090, 9091, 9092}
	for _, port := range ports {
		handler := func(payload []byte, from *i2cp.Destination) {}
		err := conn.RegisterPort(port, handler)
		if err != nil {
			t.Fatalf("RegisterPort(%d) failed: %v", port, err)
		}
	}

	// Verify all handlers were registered
	conn.mu.RLock()
	for _, port := range ports {
		if _, exists := conn.handlers[port]; !exists {
			t.Errorf("RegisterPort(%d) did not register handler", port)
		}
	}
	count := len(conn.handlers)
	conn.mu.RUnlock()

	if count != len(ports) {
		t.Errorf("RegisterPort() registered %d handlers, want %d", count, len(ports))
	}
}

// TestUnregisterPort_Success tests successful port unregistration.
func TestUnregisterPort_Success(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Register a handler
	handler := func(payload []byte, from *i2cp.Destination) {}
	err = conn.RegisterPort(9090, handler)
	if err != nil {
		t.Fatalf("RegisterPort() failed: %v", err)
	}

	// Unregister the handler
	err = conn.UnregisterPort(9090)
	if err != nil {
		t.Fatalf("UnregisterPort() failed: %v", err)
	}

	// Verify handler was removed
	conn.mu.RLock()
	_, exists := conn.handlers[9090]
	conn.mu.RUnlock()

	if exists {
		t.Error("UnregisterPort() did not remove handler")
	}
}

// TestUnregisterPort_NonExistentPort tests unregistering port that wasn't registered.
func TestUnregisterPort_NonExistentPort(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Unregister port that was never registered (should not error)
	err = conn.UnregisterPort(9090)
	if err != nil {
		t.Errorf("UnregisterPort() on non-existent port returned error: %v", err)
	}
}

// TestUnregisterPort_ClosedConnection tests unregistering on closed connection.
func TestUnregisterPort_ClosedConnection(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}

	// Close the connection
	conn.Close()

	// Try to unregister
	err = conn.UnregisterPort(9090)
	if err != net.ErrClosed {
		t.Errorf("UnregisterPort() on closed connection = %v, want net.ErrClosed", err)
	}
}

// TestRegisterPort_ConcurrentRegistration tests concurrent port registration.
func TestRegisterPort_ConcurrentRegistration(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Register ports concurrently
	const numPorts = 10
	done := make(chan bool, numPorts)

	for i := 0; i < numPorts; i++ {
		go func(port uint16) {
			handler := func(payload []byte, from *i2cp.Destination) {}
			err := conn.RegisterPort(port, handler)
			if err != nil {
				t.Errorf("RegisterPort(%d) failed: %v", port, err)
			}
			done <- true
		}(uint16(9090 + i))
	}

	// Wait for all registrations
	for i := 0; i < numPorts; i++ {
		<-done
	}

	// Verify all handlers were registered
	conn.mu.RLock()
	count := len(conn.handlers)
	conn.mu.RUnlock()

	if count != numPorts {
		t.Errorf("Concurrent RegisterPort() registered %d handlers, want %d", count, numPorts)
	}
}

// TestRegisterPort_ReregisterAfterUnregister tests re-registering a port after unregistering.
func TestRegisterPort_ReregisterAfterUnregister(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Register a handler
	handler1 := func(payload []byte, from *i2cp.Destination) {}
	err = conn.RegisterPort(9090, handler1)
	if err != nil {
		t.Fatalf("RegisterPort() first call failed: %v", err)
	}

	// Unregister
	err = conn.UnregisterPort(9090)
	if err != nil {
		t.Fatalf("UnregisterPort() failed: %v", err)
	}

	// Register again (should succeed)
	handler2 := func(payload []byte, from *i2cp.Destination) {}
	err = conn.RegisterPort(9090, handler2)
	if err != nil {
		t.Errorf("RegisterPort() after unregister failed: %v", err)
	}

	// Verify new handler was registered
	conn.mu.RLock()
	_, exists := conn.handlers[9090]
	conn.mu.RUnlock()

	if !exists {
		t.Error("RegisterPort() after unregister did not register handler")
	}
}

// TestReceiveLoop_HandlerDispatch tests that receiveLoop dispatches to registered handlers.
func TestReceiveLoop_HandlerDispatch(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Register a handler
	received := make(chan bool, 1)
	var receivedPayload []byte
	var receivedFrom *i2cp.Destination

	handler := func(payload []byte, from *i2cp.Destination) {
		receivedPayload = payload
		receivedFrom = from
		received <- true
	}

	err = conn.RegisterPort(9090, handler)
	if err != nil {
		t.Fatalf("RegisterPort() failed: %v", err)
	}

	// Inject a message for port 9090
	testPayload := []byte("test message")
	testDest := session.Destination()

	err = conn.injectMessage(testPayload, testDest, ProtocolRaw, 9090, 9090)
	if err != nil {
		t.Fatalf("injectMessage() failed: %v", err)
	}

	// Wait for handler to be called
	select {
	case <-received:
		// Handler was called
	case <-time.After(2 * time.Second):
		t.Fatal("Handler was not called within timeout")
	}

	// Verify payload and sender
	if string(receivedPayload) != string(testPayload) {
		t.Errorf("Handler received payload %q, want %q", receivedPayload, testPayload)
	}

	if receivedFrom == nil {
		t.Error("Handler received nil sender")
	}
}

// TestReceiveLoop_NoHandler tests that messages without handlers remain in queue.
func TestReceiveLoop_NoHandler(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Inject message for port with no handler
	testPayload := []byte("unhandled message")
	testDest := session.Destination()

	err = conn.injectMessage(testPayload, testDest, ProtocolRaw, 9090, 9090)
	if err != nil {
		t.Fatalf("injectMessage() failed: %v", err)
	}

	// Message should be available via ReceiveFrom
	payload, from, port, err := conn.ReceiveFrom()
	if err != nil {
		t.Fatalf("ReceiveFrom() failed: %v", err)
	}

	if string(payload) != string(testPayload) {
		t.Errorf("ReceiveFrom() payload = %q, want %q", payload, testPayload)
	}

	if port != 9090 {
		t.Errorf("ReceiveFrom() port = %d, want 9090", port)
	}

	if from == nil {
		t.Error("ReceiveFrom() returned nil sender")
	}
}

// TestReceiveLoop_MultipleHandlers tests multiple handlers on different ports.
func TestReceiveLoop_MultipleHandlers(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Register handlers for multiple ports
	port1Received := make(chan []byte, 1)
	port2Received := make(chan []byte, 1)

	handler1 := func(payload []byte, from *i2cp.Destination) {
		port1Received <- payload
	}

	handler2 := func(payload []byte, from *i2cp.Destination) {
		port2Received <- payload
	}

	err = conn.RegisterPort(9091, handler1)
	if err != nil {
		t.Fatalf("RegisterPort(9091) failed: %v", err)
	}

	err = conn.RegisterPort(9092, handler2)
	if err != nil {
		t.Fatalf("RegisterPort(9092) failed: %v", err)
	}

	// Send messages to both ports
	testDest := session.Destination()

	payload1 := []byte("message 1")
	err = conn.injectMessage(payload1, testDest, ProtocolRaw, 9091, 9091)
	if err != nil {
		t.Fatalf("injectMessage(9091) failed: %v", err)
	}

	payload2 := []byte("message 2")
	err = conn.injectMessage(payload2, testDest, ProtocolRaw, 9092, 9092)
	if err != nil {
		t.Fatalf("injectMessage(9092) failed: %v", err)
	}

	// Wait for both handlers
	select {
	case p := <-port1Received:
		if string(p) != string(payload1) {
			t.Errorf("Handler 1 received %q, want %q", p, payload1)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Handler 1 was not called within timeout")
	}

	select {
	case p := <-port2Received:
		if string(p) != string(payload2) {
			t.Errorf("Handler 2 received %q, want %q", p, payload2)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Handler 2 was not called within timeout")
	}
}

// TestReceiveLoop_CloseShutsDown tests that Close stops the receive loop.
func TestReceiveLoop_CloseShutsDown(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}

	// Register a handler
	handlerCalled := make(chan bool, 1)
	handler := func(payload []byte, from *i2cp.Destination) {
		handlerCalled <- true
	}

	err = conn.RegisterPort(9090, handler)
	if err != nil {
		t.Fatalf("RegisterPort() failed: %v", err)
	}

	// Close the connection
	err = conn.Close()
	if err != nil {
		t.Fatalf("Close() failed: %v", err)
	}

	// Try to inject message after close (should fail or be ignored)
	testDest := session.Destination()
	err = conn.injectMessage([]byte("after close"), testDest, ProtocolRaw, 9090, 9090)
	// Error expected because recvQueue is closed
	if err == nil {
		t.Error("injectMessage() after Close should return error")
	}

	// Verify handler is not called
	select {
	case <-handlerCalled:
		t.Error("Handler was called after Close()")
	case <-time.After(500 * time.Millisecond):
		// Good - handler not called
	}
}

// TestReceiveLoop_HandlerGoroutineWait tests that Close waits for handlers.
func TestReceiveLoop_HandlerGoroutineWait(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}

	// Register a slow handler
	handlerStarted := make(chan bool, 1)
	handlerFinished := make(chan bool, 1)

	handler := func(payload []byte, from *i2cp.Destination) {
		handlerStarted <- true
		time.Sleep(500 * time.Millisecond) // Simulate slow processing
		handlerFinished <- true
	}

	err = conn.RegisterPort(9090, handler)
	if err != nil {
		t.Fatalf("RegisterPort() failed: %v", err)
	}

	// Inject message to trigger handler
	testDest := session.Destination()
	err = conn.injectMessage([]byte("test"), testDest, ProtocolRaw, 9090, 9090)
	if err != nil {
		t.Fatalf("injectMessage() failed: %v", err)
	}

	// Wait for handler to start
	select {
	case <-handlerStarted:
		// Handler started
	case <-time.After(2 * time.Second):
		t.Fatal("Handler did not start within timeout")
	}

	// Close should wait for handler to finish
	closeFinished := make(chan bool, 1)
	go func() {
		conn.Close()
		closeFinished <- true
	}()

	// Wait for handler to finish
	select {
	case <-handlerFinished:
		// Handler finished
	case <-time.After(2 * time.Second):
		t.Fatal("Handler did not finish within timeout")
	}

	// Close should finish shortly after
	select {
	case <-closeFinished:
		// Close finished
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Close() did not finish after handler completed")
	}
}

// TestReceiveLoop_ConcurrentHandlers tests concurrent handler execution.
func TestReceiveLoop_ConcurrentHandlers(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Register handler that processes slowly
	const numMessages = 5
	received := make(chan int, numMessages)

	handler := func(payload []byte, from *i2cp.Destination) {
		time.Sleep(100 * time.Millisecond) // Simulate processing
		var n int
		fmt.Sscanf(string(payload), "message %d", &n)
		received <- n
	}

	err = conn.RegisterPort(9090, handler)
	if err != nil {
		t.Fatalf("RegisterPort() failed: %v", err)
	}

	// Send multiple messages quickly
	testDest := session.Destination()
	start := time.Now()

	for i := 0; i < numMessages; i++ {
		payload := []byte(fmt.Sprintf("message %d", i))
		err = conn.injectMessage(payload, testDest, ProtocolRaw, 9090, 9090)
		if err != nil {
			t.Fatalf("injectMessage(%d) failed: %v", i, err)
		}
	}

	// Collect results
	results := make(map[int]bool)
	for i := 0; i < numMessages; i++ {
		select {
		case n := <-received:
			results[n] = true
		case <-time.After(3 * time.Second):
			t.Fatalf("Did not receive all messages within timeout, got %d/%d", len(results), numMessages)
		}
	}

	elapsed := time.Since(start)

	// Verify all messages received
	if len(results) != numMessages {
		t.Errorf("Received %d unique messages, want %d", len(results), numMessages)
	}

	// Verify concurrent execution (should be < numMessages * 100ms if concurrent)
	// Allow 2x overhead for test timing variability
	maxSequential := time.Duration(numMessages) * 100 * time.Millisecond
	if elapsed > maxSequential*2 {
		t.Errorf("Processing took %v, appears sequential (expected < %v for concurrent)", elapsed, maxSequential*2)
	}
}

// TestReceiveLoop_HandlerPanic tests that handler panics don't crash receive loop.
func TestReceiveLoop_HandlerPanic(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Register handler that panics
	panicHandler := func(payload []byte, from *i2cp.Destination) {
		if string(payload) == "panic" {
			panic("intentional panic for testing")
		}
	}

	err = conn.RegisterPort(9090, panicHandler)
	if err != nil {
		t.Fatalf("RegisterPort() failed: %v", err)
	}

	// Send message that causes panic
	testDest := session.Destination()
	err = conn.injectMessage([]byte("panic"), testDest, ProtocolRaw, 9090, 9090)
	if err != nil {
		t.Fatalf("injectMessage() failed: %v", err)
	}

	// Wait a bit for handler to execute
	time.Sleep(200 * time.Millisecond)

	// Register another handler and verify receive loop still works
	goodReceived := make(chan bool, 1)
	goodHandler := func(payload []byte, from *i2cp.Destination) {
		goodReceived <- true
	}

	err = conn.RegisterPort(9091, goodHandler)
	if err != nil {
		t.Fatalf("RegisterPort(9091) failed: %v", err)
	}

	// Send message to good handler
	err = conn.injectMessage([]byte("good"), testDest, ProtocolRaw, 9091, 9091)
	if err != nil {
		t.Fatalf("injectMessage(9091) failed: %v", err)
	}

	// Verify good handler is called
	select {
	case <-goodReceived:
		// Good - receive loop still works after panic
	case <-time.After(2 * time.Second):
		t.Fatal("Receive loop appears to have stopped after handler panic")
	}
}

// TestReceiveFromWithAddr_Raw tests receiving Raw protocol datagrams with address info.
func TestReceiveFromWithAddr_Raw(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Create a test destination
	crypto := i2cp.NewCrypto()
	fromDest, _ := i2cp.NewDestination(crypto)

	// Inject a message
	payload := []byte("test message")
	err = conn.injectMessage(payload, fromDest, ProtocolRaw, 9090, 8080)
	if err != nil {
		t.Fatalf("injectMessage() failed: %v", err)
	}

	// Receive the message with address info
	receivedPayload, addr, err := conn.ReceiveFromWithAddr()
	if err != nil {
		t.Fatalf("ReceiveFromWithAddr() failed: %v", err)
	}

	// Verify payload
	if string(receivedPayload) != string(payload) {
		t.Errorf("payload = %q, want %q", receivedPayload, payload)
	}

	// Verify address has destination
	if !addr.HasFullDestination() {
		t.Error("HasFullDestination() = false, want true for Raw with known sender")
	}

	// Verify port
	if addr.Port != 9090 {
		t.Errorf("Port = %d, want 9090", addr.Port)
	}

	// Verify destination is base64 encoded
	if addr.Destination != fromDest.Base64() {
		t.Error("Destination doesn't match sender")
	}

	// Verify hash is computed
	if !addr.HasDestinationHash() {
		t.Error("HasDestinationHash() = false, want true (computed from destination)")
	}
}

// TestReceiveFromWithAddr_Datagram3 tests receiving Datagram3 protocol with hash-only sender.
func TestReceiveFromWithAddr_Datagram3(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConnWithProtocol(session, 8080, ProtocolDatagram3)
	if err != nil {
		t.Fatalf("NewDatagramConnWithProtocol() failed: %v", err)
	}
	defer conn.Close()

	// Create a test destination
	crypto := i2cp.NewCrypto()
	fromDest, _ := i2cp.NewDestination(crypto)

	// Construct Datagram3 envelope: fromhash(32) + flags(2) + payload
	payload := []byte("test message")
	destStream := i2cp.NewStream(nil)
	fromDest.WriteToStream(destStream)
	fromHash := sha256.Sum256(destStream.Bytes())

	envelope := make([]byte, 32+2+len(payload))
	copy(envelope[0:32], fromHash[:])
	envelope[32] = 0x00 // flags high byte
	envelope[33] = 0x03 // flags low byte (version 0x03)
	copy(envelope[34:], payload)

	// Inject the message with envelope
	err = conn.injectMessage(envelope, fromDest, ProtocolDatagram3, 9090, 8080)
	if err != nil {
		t.Fatalf("injectMessage() failed: %v", err)
	}

	// Receive the message with address info
	receivedPayload, addr, err := conn.ReceiveFromWithAddr()
	if err != nil {
		t.Fatalf("ReceiveFromWithAddr() failed: %v", err)
	}

	// Verify payload was extracted correctly
	if string(receivedPayload) != string(payload) {
		t.Errorf("payload = %q, want %q", receivedPayload, payload)
	}

	// Verify port
	if addr.Port != 9090 {
		t.Errorf("Port = %d, want 9090", addr.Port)
	}

	// KEY TEST: Datagram3 should be hash-only
	if !addr.IsHashOnly() {
		t.Error("IsHashOnly() = false, want true for Datagram3")
	}

	// Verify hash is populated
	if !addr.HasDestinationHash() {
		t.Error("HasDestinationHash() = false, want true for Datagram3")
	}

	// Verify the hash matches what we sent
	if addr.DestinationHash != fromHash {
		t.Errorf("DestinationHash mismatch: got %x, want %x", addr.DestinationHash, fromHash)
	}

	// Verify no full destination is available
	if addr.HasFullDestination() {
		t.Error("HasFullDestination() = true, want false for Datagram3")
	}

	// Verify Destination is empty
	if addr.Destination != "" {
		t.Errorf("Destination = %q, want empty string for Datagram3", addr.Destination)
	}
}

// TestReceiveFromWithAddr_Datagram3_WithOptions tests Datagram3 parsing with options flag set.
func TestReceiveFromWithAddr_Datagram3_WithOptions(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConnWithProtocol(session, 8080, ProtocolDatagram3)
	if err != nil {
		t.Fatalf("NewDatagramConnWithProtocol() failed: %v", err)
	}
	defer conn.Close()

	// Create a test destination
	crypto := i2cp.NewCrypto()
	fromDest, _ := i2cp.NewDestination(crypto)

	// Compute hash
	destStream := i2cp.NewStream(nil)
	fromDest.WriteToStream(destStream)
	fromHash := sha256.Sum256(destStream.Bytes())

	// Create options (empty options with 2-byte size = 0)
	options := []byte{0x00, 0x00} // size = 0

	// Construct Datagram3 envelope with options flag: fromhash(32) + flags(2) + options(2) + payload
	payload := []byte("test with options")
	envelope := make([]byte, 32+2+len(options)+len(payload))
	copy(envelope[0:32], fromHash[:])
	envelope[32] = 0x00 // flags high byte
	envelope[33] = 0x13 // flags low byte: version 0x03 + options bit (0x10)
	copy(envelope[34:], options)
	copy(envelope[34+len(options):], payload)

	// Inject the message
	err = conn.injectMessage(envelope, fromDest, ProtocolDatagram3, 9090, 8080)
	if err != nil {
		t.Fatalf("injectMessage() failed: %v", err)
	}

	// Receive the message
	receivedPayload, addr, err := conn.ReceiveFromWithAddr()
	if err != nil {
		t.Fatalf("ReceiveFromWithAddr() failed: %v", err)
	}

	// Verify payload was extracted correctly (options should be skipped)
	if string(receivedPayload) != string(payload) {
		t.Errorf("payload = %q, want %q", receivedPayload, payload)
	}

	// Verify hash is correct
	if addr.DestinationHash != fromHash {
		t.Errorf("DestinationHash mismatch")
	}
}

// TestReceiveFromWithAddr_ClosedConnection tests receiving on a closed connection.
func TestReceiveFromWithAddr_ClosedConnection(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}

	conn.Close()

	_, _, err = conn.ReceiveFromWithAddr()
	if err != net.ErrClosed {
		t.Errorf("ReceiveFromWithAddr() on closed connection error = %v, want %v", err, net.ErrClosed)
	}
}

// TestReceiveFromWithAddr_ReadDeadline tests read deadline handling.
func TestReceiveFromWithAddr_ReadDeadline(t *testing.T) {
	session := newMockSession()
	conn, err := NewDatagramConn(session, 8080)
	if err != nil {
		t.Fatalf("NewDatagramConn() failed: %v", err)
	}
	defer conn.Close()

	// Set deadline in the past
	conn.SetReadDeadline(time.Now().Add(-1 * time.Second))

	_, _, err = conn.ReceiveFromWithAddr()
	if err == nil {
		t.Error("ReceiveFromWithAddr() after deadline should return error")
	}

	if err != nil && err.Error()[:13] != "read deadline" {
		t.Errorf("unexpected error message: %v", err)
	}
}
