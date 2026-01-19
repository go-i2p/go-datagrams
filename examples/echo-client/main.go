// Echo client demonstrates sending datagrams and receiving responses.
//
// This example creates an I2CP session, sends a message to an echo server,
// and waits for the response. It showcases:
//   - I2CP session setup
//   - DatagramConn creation with Raw protocol
//   - Manual send/receive using SendTo and ReceiveFrom
//   - Read deadline for timeout handling
//
// Usage:
//
//	go run main.go <server-destination-base64>
//
// Example:
//
//	go run main.go "AAAA...base64destination...AAAA"
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/go-i2p/go-datagrams"
	i2cp "github.com/go-i2p/go-i2cp"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: echo-client <server-destination-base64>")
		fmt.Println("Example: echo-client AAAA...base64destination...AAAA")
		os.Exit(1)
	}

	serverDest := os.Args[1]

	if err := runClient(serverDest); err != nil {
		log.Fatalf("Client error: %v", err)
	}
}

// runClient creates a session, sends a message, and waits for response.
func runClient(serverDestB64 string) error {
	// Create I2CP session
	log.Println("Creating I2CP session...")

	crypto := i2cp.NewCrypto()
	localDest, err := i2cp.NewDestination(crypto)
	if err != nil {
		return fmt.Errorf("failed to create destination: %w", err)
	}

	// Create mock session for this example
	// In production, use: session, err := i2cp.NewSession(router, callbacks)
	session := &mockSession{
		dest:   localDest,
		closed: false,
	}

	log.Printf("Client I2P destination: %s", localDest.Base64())

	// Create datagram connection on port 7001 (arbitrary client port)
	conn, err := datagrams.NewDatagramConn(session, 7001)
	if err != nil {
		return fmt.Errorf("failed to create datagram connection: %w", err)
	}
	defer conn.Close()

	// Prepare message to send
	message := []byte("Hello from I2P datagram client!")
	log.Printf("Sending message to %s:7000", serverDestB64[:16]+"...")

	// Send datagram to server
	err = conn.SendTo(message, serverDestB64, 7000)
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	log.Println("Message sent, waiting for response...")

	// Set read deadline (5 second timeout)
	err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		return fmt.Errorf("failed to set read deadline: %w", err)
	}

	// Wait for response
	payload, from, port, err := conn.ReceiveFrom()
	if err != nil {
		return fmt.Errorf("failed to receive response: %w", err)
	}

	log.Printf("Received response from %s:%d", from.Base64()[:16]+"...", port)
	log.Printf("Response: %s", string(payload))

	// Verify echo
	if string(payload) == string(message) {
		log.Println("✓ Echo verification successful!")
	} else {
		log.Println("✗ Echo mismatch - received different data")
	}

	return nil
}

// mockSession is a minimal I2CPSession implementation for demonstration purposes.
// In production, use the actual i2cp.Session from go-i2cp library.
type mockSession struct {
	dest   *i2cp.Destination
	closed bool
}

func (m *mockSession) Destination() *i2cp.Destination {
	return m.dest
}

func (m *mockSession) IsClosed() bool {
	return m.closed
}

func (m *mockSession) IsOffline() bool {
	return false // Standard online keys for this example
}

func (m *mockSession) SendMessage(dest *i2cp.Destination, protocol uint8, srcPort, destPort uint16, payload *i2cp.Stream, nonce uint32) error {
	// In a real session, this would send via I2CP protocol
	time.Sleep(10 * time.Millisecond) // Simulate network delay
	return nil
}

func (m *mockSession) SendMessageWithContext(ctx context.Context, dest *i2cp.Destination, protocol uint8, srcPort, destPort uint16, payload *i2cp.Stream, nonce uint32) error {
	// In a real session, this would send via I2CP protocol with context support
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return m.SendMessage(dest, protocol, srcPort, destPort, payload, nonce)
	}
}

func (m *mockSession) SigningKeyPair() (*i2cp.Ed25519KeyPair, error) {
	// Return a generated key pair for signing operations
	crypto := i2cp.NewCrypto()
	return crypto.Ed25519SignatureKeygen()
}

func (m *mockSession) Close() error {
	m.closed = true
	return nil
}
