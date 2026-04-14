package datagrams

import (
	"fmt"
	"net"
	"time"

	i2cp "github.com/go-i2p/go-i2cp"
)

// RegisterPort registers a handler function for datagrams received on a specific port.
//
// When a datagram arrives with the given destination port number, the handler
// will be called with the payload and sender's destination. This enables
// port-based multiplexing of datagram streams over a single I2CP session.
//
// The handler is dispatched in a new goroutine to avoid blocking the receive loop.
// Handlers should be lightweight and avoid long-running operations.
//
// Parameters:
//   - port: The destination port number to listen on (0-65535)
//   - handler: Function called when a datagram arrives on this port
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
		d.wg.Add(1)
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
	defer d.wg.Done()

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
					// Message re-queued for manual ReadFrom/ReceiveFrom.
					// Sleep to prevent busy-loop: without this, an unhandled message
					// would be read and re-queued in a tight loop consuming 100% CPU.
					select {
					case <-time.After(time.Millisecond):
					case <-d.ctx.Done():
						return
					}
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
