// Echo server demonstrates basic datagram send/receive using port-based routing.
//
// This example creates an I2CP session, binds to port 7000, and echoes back
// any received datagrams to the sender. It showcases:
//   - I2CP session setup
//   - DatagramConn creation with Raw protocol (zero overhead)
//   - Port handler registration for automatic message routing
//   - Graceful shutdown on SIGINT/SIGTERM
//
// Usage:
//
//	go run main.go
//
// The server will print its I2P destination on startup. Clients can send
// datagrams to this destination:port and receive echoed responses.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-i2p/go-datagrams"
	i2cp "github.com/go-i2p/go-i2cp"
)

func main() {
	// Setup signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutdown signal received, stopping server...")
		cancel()
	}()

	// Run the echo server
	if err := runServer(ctx); err != nil && err != context.Canceled {
		log.Fatalf("Server error: %v", err)
	}

	log.Println("Server stopped cleanly")
}

// runServer initializes I2CP session and starts the echo server.
func runServer(ctx context.Context) error {
	// Create I2CP session
	// In production, configure with proper I2P router address and options
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

	log.Printf("I2P destination: %s", localDest.Base64())
	log.Println("Clients can send datagrams to: <destination>:7000")

	// Create datagram connection on port 7000
	// Using default Raw protocol (18) for zero overhead
	conn, err := datagrams.NewDatagramConn(session, 7000)
	if err != nil {
		return fmt.Errorf("failed to create datagram connection: %w", err)
	}
	defer conn.Close()

	log.Println("Echo server listening on port 7000...")

	// Register handler for port 7000
	// Handler runs in separate goroutine, so we can handle multiple messages concurrently
	err = conn.RegisterPort(7000, func(payload []byte, from *i2cp.Destination) {
		log.Printf("Received %d bytes from %s", len(payload), from.Base64()[:16]+"...")

		// Echo back to sender
		// In a real application, you'd want to handle errors here
		if from != nil {
			err := conn.SendTo(payload, from.Base64(), 7000)
			if err != nil {
				log.Printf("Failed to echo back: %v", err)
			} else {
				log.Printf("Echoed %d bytes back to sender", len(payload))
			}
		}
	})
	if err != nil {
		return fmt.Errorf("failed to register port handler: %w", err)
	}

	// Wait for shutdown signal
	<-ctx.Done()

	log.Println("Closing connection...")
	return conn.Close()
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
