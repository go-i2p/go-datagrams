package datagrams

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	i2cp "github.com/go-i2p/go-i2cp"
)

const (
	// compatConnectTimeout bounds the initial TCP/I2CP handshake with the router.
	compatConnectTimeout = 30 * time.Second

	// compatSessionTimeout bounds CreateSession. Routers under load (or i2pd
	// still building exploratory tunnels) can be slow to accept sessions.
	compatSessionTimeout = 90 * time.Second

	// compatTunnelSettleTime is how long we wait after session creation for
	// tunnel pools to build and lease sets to propagate before sending.
	compatTunnelSettleTime = 20 * time.Second

	// compatAttemptTimeout bounds a single ping/pong wait. I2P datagrams are
	// unreliable, so a full attempt may legitimately time out.
	compatAttemptTimeout = 60 * time.Second

	// compatMaxAttempts is the number of ping/pong attempts per subtest before
	// declaring the round trip failed.
	compatMaxAttempts = 3
)

// compatRouterAddress resolves the I2CP endpoint of a running router and skips
// the test if none is reachable. Environment variable conventions match both
// existing harnesses: the docker-compose stack (I2CP_HOST/I2CP_PORT) and the
// i2p-provider GitHub Action (I2P_ROUTER_I2CP_HOST/I2P_ROUTER_I2CP_PORT).
func compatRouterAddress(t *testing.T) (host, port string) {
	t.Helper()
	address := net.JoinHostPort("127.0.0.1", "7654")
	probe, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Skipf("no I2P router reachable at %s (%v); provide one via I2CP_HOST/I2CP_PORT, "+
			"the i2p-provider action, or scripts/container/test-with-router.sh", address, err)
	}
	_ = probe.Close()
	return host, port
}

// compatBridge routes messages arriving on an I2CP session to the DatagramConn
// bound to the destination port, mirroring the library's port-based routing at
// the session level. It feeds DatagramConn.injectMessage, the same seam the
// mock-based tests use, so the receive path under test is identical.
type compatBridge struct {
	mu    sync.RWMutex
	conns map[uint16]*DatagramConn
}

func newCompatBridge() *compatBridge {
	return &compatBridge{conns: make(map[uint16]*DatagramConn)}
}

// onMessage returns the i2cp.SessionCallbacks.OnMessage handler for a session.
// The payload is copied because the underlying Stream buffer is owned by the
// client's receive path.
func (b *compatBridge) onMessage(t *testing.T) func(*i2cp.Session, *i2cp.Destination, uint8, uint16, uint16, *i2cp.Stream) {
	t.Helper()
	return func(_ *i2cp.Session, srcDest *i2cp.Destination, protocol uint8, srcPort, destPort uint16, payload *i2cp.Stream) {
		data := append([]byte(nil), payload.Bytes()...)

		b.mu.RLock()
		conn, ok := b.conns[destPort]
		b.mu.RUnlock()

		if !ok {
			t.Logf("compat: dropping message for unbound port %d (protocol %d, %d bytes)", destPort, protocol, len(data))
			return
		}
		if err := conn.injectMessage(data, srcDest, protocol, srcPort, destPort); err != nil {
			t.Logf("compat: injectMessage on port %d failed: %v", destPort, err)
		}
	}
}

func (b *compatBridge) bind(port uint16, conn *DatagramConn) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.conns[port] = conn
}

func (b *compatBridge) unbind(port uint16) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.conns, port)
}

// compatEndpoint bundles everything one side of a round trip needs: a client
// connection to the router, a session on it, its I/O loop, and the bridge that
// dispatches inbound datagrams to bound DatagramConns.
type compatEndpoint struct {
	client   *i2cp.Client
	session  *i2cp.Session
	bridge   *compatBridge
	ioCancel context.CancelFunc
}

func (e *compatEndpoint) destinationB64() string {
	return e.session.Destination().Base64()
}

func (e *compatEndpoint) close() {
	if e.session != nil {
		_ = e.session.Close()
	}
	e.ioCancel()
	if e.client != nil {
		_ = e.client.Close()
	}
}

// compatProcessIO pumps the client's I/O until the context is canceled or the
// client is closed. This is the receive pump required by go-i2cp: without it,
// inbound datagrams are never dispatched to session callbacks.
func compatProcessIO(ctx context.Context, client *i2cp.Client, t *testing.T) {
	for {
		if ctx.Err() != nil {
			return
		}
		if err := client.ProcessIO(ctx); err != nil {
			if errors.Is(err, i2cp.ErrClientClosed) || ctx.Err() != nil {
				return
			}
			t.Logf("compat: ProcessIO stopped with error: %v", err)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// newCompatEndpoint connects to the router and creates a session, following the
// same async CreateSession + background ProcessIO pattern go-i2cp's own
// integration tests use against live routers.
func newCompatEndpoint(t *testing.T, host, port, nickname string) *compatEndpoint {
	t.Helper()

	client := i2cp.NewClient(&i2cp.ClientCallBacks{})
	client.SetProperty("i2cp.tcp.host", host)
	client.SetProperty("i2cp.tcp.port", port)

	connectCtx, connectCancel := context.WithTimeout(context.Background(), compatConnectTimeout)
	defer connectCancel()
	if err := client.Connect(connectCtx); err != nil {
		t.Fatalf("compat: I2CP connect to %s:%s failed: %v", host, port, err)
	}

	bridge := newCompatBridge()
	created := make(chan struct{}, 1)
	session := i2cp.NewSession(client, i2cp.SessionCallbacks{
		OnMessage: bridge.onMessage(t),
		OnStatus: func(s *i2cp.Session, status i2cp.SessionStatus) {
			if status == i2cp.I2CP_SESSION_STATUS_CREATED {
				select {
				case created <- struct{}{}:
				default:
				}
			}
		},
	})
	session.Config().SetProperty(i2cp.SESSION_CONFIG_PROP_I2CP_FAST_RECEIVE, "true")
	session.Config().SetProperty(i2cp.SESSION_CONFIG_PROP_OUTBOUND_NICKNAME, nickname)

	ioCtx, ioCancel := context.WithCancel(context.Background())
	go compatProcessIO(ioCtx, client, t)

	createCtx, createCancel := context.WithTimeout(context.Background(), compatSessionTimeout)
	defer createCancel()
	if err := client.CreateSession(createCtx, session); err != nil {
		ioCancel()
		_ = client.Close()
		t.Fatalf("compat: CreateSession failed: %v", err)
	}

	select {
	case <-created:
		t.Logf("compat: session %d created (%s)", session.ID(), nickname)
	case <-createCtx.Done():
		ioCancel()
		_ = client.Close()
		t.Fatalf("compat: timed out waiting for session creation (%s)", nickname)
	}

	ep := &compatEndpoint{client: client, session: session, bridge: bridge, ioCancel: ioCancel}
	t.Cleanup(ep.close)
	return ep
}

// compatBind creates a DatagramConn for the given protocol on the endpoint's
// session and registers it in the bridge under its local port.
func compatBind(t *testing.T, ep *compatEndpoint, protocol uint8, localPort uint16) *DatagramConn {
	t.Helper()

	conn, err := NewDatagramConnWithProtocol(ep.session, localPort, protocol)
	if err != nil {
		t.Fatalf("compat: NewDatagramConnWithProtocol(%d, port %d) failed: %v", protocol, localPort, err)
	}
	ep.bridge.bind(localPort, conn)
	t.Cleanup(func() {
		// Unbind before Close so the bridge cannot inject into a closed queue.
		ep.bridge.unbind(localPort)
		_ = conn.Close()
	})
	return conn
}

// compatDoRoundTrip runs body up to compatMaxAttempts times, tolerating lost
// datagrams. Protocol violations (bad payload, wrong sender) should fail the
// test directly from inside body via t.Fatalf; only delivery timeouts return
// errors for retry.
func compatDoRoundTrip(t *testing.T, name string, body func(attempt int) error) {
	t.Helper()

	var err error
	for attempt := 1; attempt <= compatMaxAttempts; attempt++ {
		if err = body(attempt); err == nil {
			return
		}
		t.Logf("%s: attempt %d/%d did not complete: %v", name, attempt, compatMaxAttempts, err)
	}
	t.Fatalf("%s: round trip failed after %d attempts (last error: %v)", name, compatMaxAttempts, err)
}

// TestDatagramSessionRoundTrip verifies bidirectional datagram delivery between
// two sessions on a real router for every protocol this library supports.
//
// Two endpoints (separate I2CP clients and sessions) are created once and
// shared across subtests so tunnel establishment cost is paid once. Each
// subtest binds a fresh pair of DatagramConns on unique ports, then:
//
//  1. sends a ping A -> B and verifies payload integrity and source port,
//  2. verifies sender identification per protocol semantics:
//     Raw: none (non-repliable); Datagram1/2: full authenticated destination;
//     Datagram3: hash-only via ReceiveFromWithAddr,
//  3. sends a pong B -> A (using the authenticated sender destination for
//     Datagram1/2, proving repliability) and verifies it on A.
func TestDatagramSessionRoundTrip(t *testing.T) {
	host, port := compatRouterAddress(t)

	epA := newCompatEndpoint(t, host, port, "go-datagrams-compat-a")
	epB := newCompatEndpoint(t, host, port, "go-datagrams-compat-b")
	t.Logf("compat: endpoint A destination (b32): %s", epA.session.Destination().Base32())
	t.Logf("compat: endpoint B destination (b32): %s", epB.session.Destination().Base32())

	t.Logf("compat: waiting %s for tunnel establishment and lease set propagation", compatTunnelSettleTime)
	time.Sleep(compatTunnelSettleTime)

	protocols := []struct {
		name     string
		protocol uint8
	}{
		{"Raw", ProtocolRaw},
		{"Datagram1", ProtocolDatagram1},
		{"Datagram2", ProtocolDatagram2},
		{"Datagram3", ProtocolDatagram3},
	}

	for _, p := range protocols {
		t.Run(p.name, func(t *testing.T) {
			if p.protocol == ProtocolDatagram1 {
				t.Log("note: go-i2cp dissects Datagram1 envelopes at the I2CP layer, " +
					"so the sender identity asserted here is parsed but not signature-verified by DatagramConn")
			}
			portA := uint16(9000) + uint16(p.protocol)
			portB := uint16(9100) + uint16(p.protocol)
			connA := compatBind(t, epA, p.protocol, portA)
			connB := compatBind(t, epB, p.protocol, portB)

			nonce := time.Now().UnixNano()
			ping := []byte(fmt.Sprintf("go-datagrams compat ping proto=%d nonce=%d", p.protocol, nonce))
			pong := []byte(fmt.Sprintf("go-datagrams compat pong proto=%d nonce=%d", p.protocol, nonce))

			wantHashA, err := destinationHash(epA.session.Destination())
			if err != nil {
				t.Fatalf("compat: failed to hash endpoint A destination: %v", err)
			}
			wantHashB, err := destinationHash(epB.session.Destination())
			if err != nil {
				t.Fatalf("compat: failed to hash endpoint B destination: %v", err)
			}

			compatDoRoundTrip(t, p.name, func(attempt int) error {
				if err := connA.SendTo(ping, epB.destinationB64(), portB); err != nil {
					t.Fatalf("ping send failed (not retryable): %v", err)
				}

				replyDest := epA.destinationB64()
				if p.protocol == ProtocolDatagram3 {
					if err := compatExpectPingDatagram3(t, connB, ping, wantHashA, portA); err != nil {
						return err
					}
				} else {
					from, err := compatExpectPing(t, connB, p.protocol, ping, epA.destinationB64(), portA)
					if err != nil {
						return err
					}
					// Repliable protocols: reply to the authenticated sender
					// destination from the datagram itself, not test knowledge.
					if from != "" {
						replyDest = from
					}
				}

				if err := connB.SendTo(pong, replyDest, portA); err != nil {
					t.Fatalf("pong send failed (not retryable): %v", err)
				}

				if p.protocol == ProtocolDatagram3 {
					return compatExpectPongDatagram3(t, connA, pong, wantHashB, portB)
				}
				return compatExpectPong(t, connA, p.protocol, pong, epB.destinationB64(), portB)
			})
		})
	}
}

// compatExpectPing waits for the ping on B and verifies payload, source port,
// and sender identity for protocols carrying a full destination (Raw may
// report none; Datagram1/2 must authenticate as A). It returns the verified
// sender destination, or "" if the protocol provides none.
func compatExpectPing(t *testing.T, connB *DatagramConn, protocol uint8, ping []byte, destA string, portA uint16) (string, error) {
	t.Helper()

	if err := connB.SetReadDeadline(time.Now().Add(compatAttemptTimeout)); err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}
	payload, from, srcPort, err := connB.ReceiveFrom()
	if err != nil {
		return "", fmt.Errorf("ping not received: %w", err)
	}

	if string(payload) != string(ping) {
		t.Fatalf("ping payload mismatch: got %q, want %q", payload, ping)
	}
	if srcPort != portA {
		t.Fatalf("ping source port mismatch: got %d, want %d", srcPort, portA)
	}

	switch protocol {
	case ProtocolRaw:
		// Raw is non-repliable; the router is not required to identify the sender.
		return "", nil
	case ProtocolDatagram1, ProtocolDatagram2:
		if from == nil {
			t.Fatalf("protocol %d must carry an authenticated sender destination, got nil", protocol)
		}
		if from.Base64() != destA {
			t.Fatalf("ping sender mismatch: got %s..., want endpoint A", from.Base64()[:16])
		}
		return from.Base64(), nil
	default:
		t.Fatalf("compatExpectPing does not handle protocol %d", protocol)
		return "", nil
	}
}

// compatExpectPong waits for the pong on A with the same checks as
// compatExpectPing, mirrored for the B -> A direction.
func compatExpectPong(t *testing.T, connA *DatagramConn, protocol uint8, pong []byte, destB string, portB uint16) error {
	t.Helper()

	if err := connA.SetReadDeadline(time.Now().Add(compatAttemptTimeout)); err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}
	payload, from, srcPort, err := connA.ReceiveFrom()
	if err != nil {
		return fmt.Errorf("pong not received: %w", err)
	}

	if string(payload) != string(pong) {
		t.Fatalf("pong payload mismatch: got %q, want %q", payload, pong)
	}
	if srcPort != portB {
		t.Fatalf("pong source port mismatch: got %d, want %d", srcPort, portB)
	}

	switch protocol {
	case ProtocolRaw:
		return nil
	case ProtocolDatagram1, ProtocolDatagram2:
		if from == nil {
			t.Fatalf("protocol %d must carry an authenticated sender destination, got nil", protocol)
		}
		if from.Base64() != destB {
			t.Fatalf("pong sender mismatch: got %s..., want endpoint B", from.Base64()[:16])
		}
		return nil
	default:
		t.Fatalf("compatExpectPong does not handle protocol %d", protocol)
		return nil
	}
}

// compatExpectPingDatagram3 waits for the ping on B using ReceiveFromWithAddr,
// since Datagram3 carries only the sender's 32-byte destination hash.
func compatExpectPingDatagram3(t *testing.T, connB *DatagramConn, ping []byte, wantHashA [32]byte, portA uint16) error {
	t.Helper()

	if err := connB.SetReadDeadline(time.Now().Add(compatAttemptTimeout)); err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}
	payload, addr, err := connB.ReceiveFromWithAddr()
	if err != nil {
		return fmt.Errorf("ping not received: %w", err)
	}

	if string(payload) != string(ping) {
		t.Fatalf("ping payload mismatch: got %q, want %q", payload, ping)
	}
	if addr.Port != portA {
		t.Fatalf("ping source port mismatch: got %d, want %d", addr.Port, portA)
	}
	if !addr.IsHashOnly() {
		t.Fatalf("Datagram3 sender must be hash-only, got address %s", addr)
	}
	if addr.DestinationHash != wantHashA {
		t.Fatalf("ping sender hash mismatch: got %x, want hash of endpoint A", addr.DestinationHash[:8])
	}
	return nil
}

// compatExpectPongDatagram3 is compatExpectPingDatagram3 mirrored for the
// B -> A direction.
func compatExpectPongDatagram3(t *testing.T, connA *DatagramConn, pong []byte, wantHashB [32]byte, portB uint16) error {
	t.Helper()

	if err := connA.SetReadDeadline(time.Now().Add(compatAttemptTimeout)); err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}
	payload, addr, err := connA.ReceiveFromWithAddr()
	if err != nil {
		return fmt.Errorf("pong not received: %w", err)
	}

	if string(payload) != string(pong) {
		t.Fatalf("pong payload mismatch: got %q, want %q", payload, pong)
	}
	if addr.Port != portB {
		t.Fatalf("pong source port mismatch: got %d, want %d", addr.Port, portB)
	}
	if !addr.IsHashOnly() {
		t.Fatalf("Datagram3 sender must be hash-only, got address %s", addr)
	}
	if addr.DestinationHash != wantHashB {
		t.Fatalf("pong sender hash mismatch: got %x, want hash of endpoint B", addr.DestinationHash[:8])
	}
	return nil
}

// TestDatagramSessionRoundTrip_PacketConn exercises the standard net.PacketConn
// interface (WriteTo/ReadFrom with I2PAddr) over a real router, verifying that
// the compatibility surface existing Go networking code would use also works
// end to end.
func TestDatagramSessionRoundTrip_PacketConn(t *testing.T) {
	host, port := compatRouterAddress(t)

	epA := newCompatEndpoint(t, host, port, "go-datagrams-compat-packetconn-a")
	epB := newCompatEndpoint(t, host, port, "go-datagrams-compat-packetconn-b")

	t.Logf("compat: waiting %s for tunnel establishment and lease set propagation", compatTunnelSettleTime)
	time.Sleep(compatTunnelSettleTime)

	const (
		portA uint16 = 9180
		portB uint16 = 9181
	)
	connA := compatBind(t, epA, ProtocolRaw, portA)
	connB := compatBind(t, epB, ProtocolRaw, portB)

	ping := []byte(fmt.Sprintf("go-datagrams packetconn ping nonce=%d", time.Now().UnixNano()))
	pong := []byte("go-datagrams packetconn pong")

	compatDoRoundTrip(t, "PacketConn", func(attempt int) error {
		addrB := &I2PAddr{Destination: epB.destinationB64(), Port: portB}
		if n, err := connA.WriteTo(ping, addrB); err != nil {
			t.Fatalf("WriteTo ping failed (not retryable): %v", err)
		} else if n != len(ping) {
			t.Fatalf("WriteTo ping wrote %d bytes, want %d", n, len(ping))
		}

		if err := connB.SetReadDeadline(time.Now().Add(compatAttemptTimeout)); err != nil {
			t.Fatalf("SetReadDeadline failed: %v", err)
		}
		buf := make([]byte, 2048)
		n, from, err := connB.ReadFrom(buf)
		if err != nil {
			return fmt.Errorf("ping not received: %w", err)
		}
		fromAddr, ok := from.(*I2PAddr)
		if !ok {
			t.Fatalf("ReadFrom returned %T, want *I2PAddr", from)
		}
		if string(buf[:n]) != string(ping) {
			t.Fatalf("ping payload mismatch: got %q, want %q", buf[:n], ping)
		}
		if fromAddr.Port != portA {
			t.Fatalf("ping source port mismatch: got %d, want %d", fromAddr.Port, portA)
		}

		addrA := &I2PAddr{Destination: epA.destinationB64(), Port: portA}
		if _, err := connB.WriteTo(pong, addrA); err != nil {
			t.Fatalf("WriteTo pong failed (not retryable): %v", err)
		}

		if err := connA.SetReadDeadline(time.Now().Add(compatAttemptTimeout)); err != nil {
			t.Fatalf("SetReadDeadline failed: %v", err)
		}
		n, _, err = connA.ReadFrom(buf)
		if err != nil {
			return fmt.Errorf("pong not received: %w", err)
		}
		if string(buf[:n]) != string(pong) {
			t.Fatalf("pong payload mismatch: got %q, want %q", buf[:n], pong)
		}
		return nil
	})
}
