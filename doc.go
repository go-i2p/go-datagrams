// Package datagrams provides stateless, port-based messaging over I2P.
//
// This library wraps I2CP datagram sessions,
// implementing Go's standard net.PacketConn interface for compatibility with existing networking code.
//
// # I2P Datagram Types
//
// I2P supports four datagram types with different trade-offs:
//
//   - Raw (Protocol 18): Non-repliable, no authentication, 0 bytes overhead
//     Use for: Performance-critical applications with trusted peers
//
//   - Datagram1 (Protocol 17): Repliable, authenticated, ~455 bytes overhead (Ed25519)
//     Use for: Legacy compatibility with older I2P applications
//
//   - Datagram2 (Protocol 19): Repliable, authenticated with replay prevention, ~457+ bytes overhead (Ed25519)
//     Use for: Modern authenticated messaging requiring replay attack prevention
//
//   - Datagram3 (Protocol 20): Repliable, no authentication, ~34 bytes overhead
//     Use for: Lightweight repliable messages with minimal overhead
//
// # Size Limits
//
// The practical size limit for reliable delivery is 8-10KB. While I2CP supports up to ~64KB datagrams,
// larger messages are fragmented into 1KB tunnel messages with exponentially increasing drop probability.
//
// # Stateless Design
//
// Unlike TCP connections, I2P datagrams are stateless. Each message is independent with no automatic
// retransmission, ordering, or connection state. Applications requiring reliability must implement it
// at the application layer using sequence numbers, ACKs, and retransmission logic.
//
// # Basic Usage
//
// Create a datagram connection and send/receive messages:
//
//	session, _ := i2cp.NewSession(config)
//	conn, _ := datagrams.NewDatagramConn(session, 8080)
//	defer conn.Close()
//
//	// Send a message
//	addr := &datagrams.I2PAddr{
//	    Destination: "example.i2p.destination.string",
//	    Port:        8081,
//	}
//	conn.WriteTo([]byte("Hello"), addr)
//
//	// Receive a message
//	buf := make([]byte, 8192)
//	n, addr, _ := conn.ReadFrom(buf)
//	fmt.Printf("Received: %s\n", buf[:n])
//
// # Port-Based Routing
//
// This library provides port-based message routing to allow multiple services to share
// a single I2CP session. Each DatagramConn is bound to a local port, enabling:
//
//   - Multiple application protocols per I2CP session
//   - Port-based message filtering and dispatch
//   - Familiar networking semantics for Go developers
//
// Applications that don't need port-based routing can use Raw datagrams with minimal overhead.
package datagrams
