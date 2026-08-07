package softun

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/KarpelesLab/pktkit"
	"github.com/KarpelesLab/pktkit/vtcp"
)

// loEcho is a tiny loopback TCP echo server used to simulate a local
// 127.0.0.1 service reached through the port map.
type loEcho struct {
	ln       net.Listener
	conns    map[net.Conn]struct{}
	mu       sync.Mutex
	accepted chan struct{}
}

func newLoEcho(t *testing.T) *loEcho {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e := &loEcho{ln: ln, conns: make(map[net.Conn]struct{}), accepted: make(chan struct{}, 64)}
	go e.serve()
	return e
}

func (e *loEcho) port() int {
	return e.ln.Addr().(*net.TCPAddr).Port
}

func (e *loEcho) serve() {
	for {
		c, err := e.ln.Accept()
		if err != nil {
			return
		}
		e.accepted <- struct{}{}
		e.mu.Lock()
		e.conns[c] = struct{}{}
		e.mu.Unlock()
		go func() {
			io.Copy(c, c)
			e.mu.Lock()
			delete(e.conns, c)
			e.mu.Unlock()
			c.Close()
		}()
	}
}

func (e *loEcho) close() {
	e.ln.Close()
	e.mu.Lock()
	for c := range e.conns {
		c.Close()
	}
	e.mu.Unlock()
}

// waitAccepts waits until at least n connections were accepted by the echo.
func (e *loEcho) waitAccepts(n int) bool {
	deadline := time.After(3 * time.Second)
	got := 0
	for got < n {
		select {
		case <-e.accepted:
			got++
		case <-deadline:
			return false
		}
	}
	return true
}

// synToLocal builds a SYN packet from a remote virtual node to a local port.
func synToLocal(remote netip.Addr, port uint16) pktkit.Packet {
	return makeTCP(remote, netip.MustParseAddr(LocalIP()), &vtcp.Segment{
		SrcPort: 50000, DstPort: port, Seq: 1000, Flags: vtcp.FlagSYN, Window: 65535,
	})
}

func TestLoPortMapEcho(t *testing.T) {
	EnableLoPortMap()
	defer DisableLoPortMap()

	e := newLoEcho(t)
	defer e.close()
	port := e.port()

	addr := LocalIP() + ":" + strconv.Itoa(port)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := softTun.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	msg := "hello-lo-portmap"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != msg {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}

	lpmMu.Lock()
	registered := len(lpmListeners) > 0
	lpmMu.Unlock()
	if !registered {
		t.Fatal("no proxy listener registered")
	}

	DisableLoPortMap()
	lpmMu.Lock()
	left := len(lpmListeners)
	lpmMu.Unlock()
	if left != 0 {
		t.Fatalf("proxy listeners left after disable: %d", left)
	}
}

func TestLoPortMapRemoteSYN(t *testing.T) {
	EnableLoPortMap()
	defer DisableLoPortMap()

	e := newLoEcho(t)
	defer e.close()
	port := e.port()

	if !handleInboundTCP(synToLocal(netip.MustParseAddr("10.0.0.5"), uint16(port))) {
		t.Fatal("handleInboundTCP did not claim SYN")
	}

	// Capture the stack's SYN-ACK while keeping routeWrite in the path so the
	// SYN-pending marker is cleared as usual, then complete the handshake as
	// the remote peer would.
	synackCh := make(chan pktkit.Packet, 4)
	old := routeWrite
	softTun.SetHandler(func(pkt pktkit.Packet) error {
		if pkt.IPProtocol() == pktkit.ProtocolTCP {
			if flags, ok := tcpFlags(pkt); ok &&
				flags&(vtcp.FlagSYN|vtcp.FlagACK) == vtcp.FlagSYN|vtcp.FlagACK &&
				pkt.DstAddr() == netip.MustParseAddr("10.0.0.5") {
				cp := make(pktkit.Packet, len(pkt))
				copy(cp, pkt)
				select {
				case synackCh <- cp:
				default:
				}
			}
		}
		return old(pkt)
	})
	defer softTun.SetHandler(old)

	if !handleInboundTCP(synToLocal(netip.MustParseAddr("10.0.0.5"), uint16(port))) {
		t.Fatal("handleInboundTCP did not claim SYN")
	}

	select {
	case synack := <-synackCh:
		seg, err := vtcp.ParseSegment(synack.Payload())
		if err != nil {
			t.Fatalf("parse SYN-ACK: %v", err)
		}
		ack := &vtcp.Segment{
			SrcPort: seg.DstPort, DstPort: seg.SrcPort,
			Seq: seg.Ack, Ack: seg.Seq + seg.SegLen(),
			Flags: vtcp.FlagACK, Window: 65535,
		}
		softTun.Send(makeTCP(netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr(LocalIP()), ack))
	case <-time.After(3 * time.Second):
		t.Fatal("no SYN-ACK captured")
	}
	lpmMu.Lock()
	_, ok := lpmListeners[uint16(port)]
	lpmMu.Unlock()
	if !ok {
		t.Fatal("proxy listener not registered for remote SYN")
	}

	// ...and the bridge must have connected to the loopback service. Two
	// accepts expected: the loportmap probe and the bridged connection.
	if !e.waitAccepts(2) {
		t.Fatal("bridge did not connect to loopback service")
	}
}

func TestLoPortMapRefused(t *testing.T) {
	EnableLoPortMap()
	defer DisableLoPortMap()

	port := freePort(t)
	if !handleInboundTCP(synToLocal(netip.MustParseAddr("10.0.0.5"), uint16(port))) {
		t.Fatal("handleInboundTCP did not claim SYN")
	}
	lpmMu.Lock()
	_, ok := lpmListeners[uint16(port)]
	lpmMu.Unlock()
	if ok {
		t.Fatal("proxy listener registered for a port with no loopback service")
	}
}

func TestLoPortMapGC(t *testing.T) {
	EnableLoPortMap()
	defer DisableLoPortMap()

	e := newLoEcho(t)
	defer e.close()
	port := e.port()

	if !handleInboundTCP(synToLocal(netip.MustParseAddr("10.0.0.5"), uint16(port))) {
		t.Fatal("handleInboundTCP did not claim SYN")
	}

	// Age the entry past the TTL and reap.
	lpmMu.Lock()
	e2, ok := lpmListeners[uint16(port)]
	if !ok {
		lpmMu.Unlock()
		t.Fatal("proxy listener not registered")
	}
	e2.lastTouched = time.Now().Add(-lpmTTL - time.Second)
	lpmMu.Unlock()

	reapLoPortMap(time.Now())

	lpmMu.Lock()
	_, ok = lpmListeners[uint16(port)]
	lpmMu.Unlock()
	if ok {
		t.Fatal("idle proxy listener not reaped")
	}

	// The virtual port must be released for the application again.
	l, err := softTun.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("port not released after GC: %v", err)
	}
	l.Close()
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
