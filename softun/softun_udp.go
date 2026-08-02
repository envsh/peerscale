package softun

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/KarpelesLab/pktkit"
)

var (
	udpLstMu    sync.Mutex
	udpListeners = make(map[uint16]*udpListener)
)

type udpDatagram struct {
	data []byte
	addr net.Addr
}

// udpListener is a user-space UDP listener implementing net.PacketConn. It is
// stateless per remote (no NAT-style sessions), so there is no idle state to
// reap — datagrams for the bound port are delivered regardless of sender.
type udpListener struct {
	port    uint16
	recvCh  chan udpDatagram
	closeCh chan struct{}
	once    sync.Once
}

var _ net.PacketConn = (*udpListener)(nil)

// ListenUDP binds a virtual UDP port and returns a net.PacketConn that
// receives datagrams addressed to this node on that port. WriteTo sends a
// datagram from this node's virtual address and port to the given address.
func ListenUDP(port uint16) (net.PacketConn, error) {
	ensureInit()
	udpLstMu.Lock()
	defer udpLstMu.Unlock()
	if udpListeners[port] != nil {
		return nil, errors.New("softun: address already in use")
	}
	l := &udpListener{
		port:    port,
		recvCh:  make(chan udpDatagram, 64),
		closeCh: make(chan struct{}),
	}
	udpListeners[port] = l
	return l, nil
}

func (l *udpListener) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case d := <-l.recvCh:
		return copy(b, d.data), d.addr, nil
	case <-l.closeCh:
		return 0, nil, net.ErrClosed
	}
}

func (l *udpListener) WriteTo(p []byte, addr net.Addr) (int, error) {
	a, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("softun: invalid address type")
	}
	ip := a.IP
	if ip == nil {
		return 0, errors.New("softun: missing destination IP")
	}
	payload := make([]byte, 8+len(p))
	binary.BigEndian.PutUint16(payload[0:2], l.port)
	binary.BigEndian.PutUint16(payload[2:4], uint16(a.Port))
	binary.BigEndian.PutUint16(payload[4:6], uint16(8+len(p)))
	copy(payload[8:], p)

	var pkt []byte
	if ip4 := ip.To4(); ip4 != nil {
		pkt = wrapIPv4(localAddr4(), netip.AddrFrom4([4]byte(ip4)), uint8(pktkit.ProtocolUDP), payload)
	} else {
		src := localAddr6()
		if !src.IsValid() {
			return 0, errors.New("softun: local IPv6 address not configured")
		}
		pkt = wrapIPv6(src, netip.AddrFrom16([16]byte(ip.To16())), uint8(pktkit.ProtocolUDP), payload)
	}
	if err := routeWrite(pktkit.Packet(pkt)); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (l *udpListener) Close() error {
	l.once.Do(func() {
		close(l.closeCh)
		udpLstMu.Lock()
		delete(udpListeners, l.port)
		udpLstMu.Unlock()
	})
	return nil
}

func (l *udpListener) SetDeadline(t time.Time) error      { return nil }
func (l *udpListener) SetReadDeadline(t time.Time) error  { return nil }
func (l *udpListener) SetWriteDeadline(t time.Time) error { return nil }

func (l *udpListener) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IP(netip.MustParseAddr(LocalIP()).AsSlice()), Port: int(l.port)}
}

// handleInboundUDP delivers a UDP datagram addressed to a bound listener port
// and reports whether it was consumed.
func handleInboundUDP(pkt pktkit.Packet) bool {
	pl := pkt.Payload()
	if len(pl) < 8 {
		return false
	}
	dstPort := binary.BigEndian.Uint16(pl[2:4])
	udpLstMu.Lock()
	l := udpListeners[dstPort]
	udpLstMu.Unlock()
	if l == nil {
		return false
	}
	udpLen := binary.BigEndian.Uint16(pl[4:6])
	if udpLen < 8 || int(udpLen) > len(pl) {
		return true // malformed datagram addressed to a bound port: consume
	}
	data := make([]byte, int(udpLen)-8)
	copy(data, pl[8:udpLen])
	d := udpDatagram{
		data: data,
		addr: &net.UDPAddr{IP: net.IP(pkt.SrcAddr().AsSlice()), Port: int(binary.BigEndian.Uint16(pl[0:2]))},
	}
	select {
	case l.recvCh <- d:
	case <-l.closeCh:
	}
	return true
}

func localAddr4() netip.Addr {
	return netip.MustParseAddr(LocalIP())
}

func localAddr6() netip.Addr {
	v6 := LocalIPv6()
	if v6 == "" {
		return netip.Addr{}
	}
	a, _ := netip.ParseAddr(v6)
	return a
}
