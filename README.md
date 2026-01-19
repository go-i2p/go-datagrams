# go-datagrams

A Go library for sending and receiving I2P datagrams over I2CP.

## Overview

`go-datagrams` provides a stateless, port-based messaging layer for I2P applications. It wraps I2CP datagram sessions, implementing Go's standard `net.PacketConn` interface for compatibility with existing networking code.

**Key Features:**

- Stateless datagram send/receive over I2CP
- Port-based message routing on a single I2P session
- Standard `net.PacketConn` interface implementation
- Support for Raw (protocol 18), Datagram1 (protocol 17), Datagram2 (protocol 19), and Datagram3 (protocol 20)
- Thread-safe concurrent operations

## Installation

```bash
go get github.com/go-i2p/go-datagrams
```

**Requirements:**

- Go 1.21+
- Access to an I2P router with I2CP enabled
- `github.com/go-i2p/go-i2cp` for I2CP transport

## Quick Start

```go
package main

import (
    "fmt"
    "github.com/go-i2p/go-datagrams"
    "github.com/go-i2p/go-i2cp"
)

func main() {
    // Initialize I2CP session (see go-i2cp documentation)
    session, err := i2cp.NewSession(/* config */)
    if err != nil {
        panic(err)
    }
    defer session.Close()

    // Create datagram connection
    conn, err := datagrams.NewDatagramConn(session, 8080)
    if err != nil {
        panic(err)
    }
    defer conn.Close()

    // Send a datagram
    payload := []byte("Hello, I2P!")
    destAddr := &datagrams.I2PAddr{
        Destination: "example.i2p.destination.string",
        Port:        8081,
    }
    _, err = conn.WriteTo(payload, destAddr)
    if err != nil {
        panic(err)
    }

    // Receive a datagram
    buf := make([]byte, 8192)
    n, addr, err := conn.ReadFrom(buf)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Received %d bytes from %s: %s\n", n, addr, buf[:n])
}
```

## Architecture

### Datagram Types

I2P supports multiple datagram types with different trade-offs:

| Type | Protocol | Authenticated? | Repliable? | Overhead | Use Case |
|------|----------|----------------|------------|----------|----------|
| Raw | 18 | No | No | 0 bytes | Low-latency, high-throughput |
| Datagram1 | 17 | Yes | Yes | ~427 bytes | Legacy authenticated messaging |
| Datagram2 | 19 | Yes | Yes | ~433+ bytes | Modern authenticated with replay prevention |
| Datagram3 | 20 | No | Yes | ~34 bytes | Lightweight repliable |

**Recommendation:** Use Raw datagrams for performance, Datagram3 for repliability with minimal overhead, or Datagram2 for authentication with replay protection.

### Size Limits

- **Maximum I2CP datagram**: ~31KB (nominal 64KB minus overhead)
- **Recommended maximum**: 8-10KB for reliable delivery

I2NP messages are fragmented into 1KB tunnel messages. Larger datagrams have exponentially higher drop probability due to fragmentation.

### Port-Based Routing

Multiple application protocols can share a single I2CP session by registering handlers for specific ports:

```go
conn.RegisterPort(8080, func(payload []byte, from i2cp.Destination) {
    // Handle incoming messages on port 8080
    fmt.Printf("Received %d bytes from %s\n", len(payload), from)
})
```

## Design Principles

Following the patterns from [copilot-instructions.md](.github/copilot-instructions.md):

- **Stateless operation**: No connection state tracking (matches I2CP datagram semantics)
- **Standard interfaces**: Implements `net.PacketConn` and `net.Addr`
- **Thread safety**: All operations are safe for concurrent use
- **No IP assumptions**: Works with I2P destinations, not IP addresses

## Limitations

**Cryptographic Requirements:**

- **Ed25519 only**: This library exclusively supports Ed25519 destinations and signatures. Legacy DSA_SHA1, ElGamal, and ECDSA signature types are not supported. This aligns with go-i2cp's Ed25519-only approach and I2P's direction toward modern cryptography.

**I2P Datagram Characteristics:**

- **Unreliable delivery**: No automatic retransmission or ordering guarantees
- **No connection state**: Each datagram is independent
- **Size-dependent reliability**: Larger datagrams (>10KB) have significantly higher drop rates
- **End-to-end unreliability**: Messages may be dropped at any hop despite reliable hop-to-hop transport

Applications requiring reliability must implement it at the application layer (ACKs, sequence numbers, retransmission).

## Documentation

- [Datagram Specification (SPEC.md)](SPEC.md) - Full I2P datagram protocol specification
- [Implementation Roadmap (ROADMAP.md)](ROADMAP.md) - Development plan and design decisions
- [I2P Datagram API Overview](https://geti2p.net/en/docs/api/datagrams)
- [go-i2cp Documentation](https://github.com/go-i2p/go-i2cp)

## License

See [LICENSE](LICENSE) file for details.
