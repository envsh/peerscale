package softun

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/KarpelesLab/pktkit"
	"github.com/KarpelesLab/pktkit/slirp"
	"github.com/KarpelesLab/pktkit/vtcp"
)

func TestMain(m *testing.M) {
	localMu.Lock()
	localPeerID = "softun-test-node"
	localMu.Unlock()
	InitSoftTun("softun-test-node")
	os.Exit(m.Run())
}

func TestLocalIPv6(t *testing.T) {
	h := StringToHostPart("softun-test-node")
	if got := LocalIPv6(); got != ipv6pfx+strconv.FormatInt(int64(h), 16) {
		t.Fatalf("LocalIPv6() = %q, want fd00::%x", got, h)
	}
	if LocalIP() != vlanpfx+strconv.Itoa(h) {
		t.Fatalf("LocalIP() = %q, host part %d", LocalIP(), h)
	}
}

// makeICMPv4Echo builds an IPv4 packet carrying an ICMP echo request.
func makeICMPv4Echo(src, dst netip.Addr, id, seq uint16, payload string) pktkit.Packet {
	icmp := make([]byte, 8+len(payload))
	icmp[0] = 8 // echo request
	binary.BigEndian.PutUint16(icmp[4:6], id)
	binary.BigEndian.PutUint16(icmp[6:8], seq)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], pktkit.Checksum(icmp))

	hdr := make([]byte, 20)
	hdr[0] = 0x45
	binary.BigEndian.PutUint16(hdr[2:4], uint16(20+len(icmp)))
	hdr[9] = 1
	s4, d4 := src.As4(), dst.As4()
	copy(hdr[12:16], s4[:])
	copy(hdr[16:20], d4[:])
	return append(hdr, icmp...)
}

func TestBuildICMPv4Reply(t *testing.T) {
	src := netip.MustParseAddr("10.0.0.5")
	dst := netip.MustParseAddr("10.0.0.9")
	req := makeICMPv4Echo(src, dst, 0x1234, 7, "pingdata")

	reply := pktkit.Packet(buildICMPv4Reply(req))
	if reply == nil {
		t.Fatal("buildICMPv4Reply returned nil")
	}
	if reply.Version() != 4 {
		t.Fatalf("reply version = %d", reply.Version())
	}
	if reply.IPv4SrcAddr() != dst || reply.IPv4DstAddr() != src {
		t.Fatalf("addresses not reversed: src=%s dst=%s", reply.IPv4SrcAddr(), reply.IPv4DstAddr())
	}
	icmp := reply.IPv4Payload()
	if icmp[0] != 0 {
		t.Fatalf("ICMP type = %d, want 0 (echo reply)", icmp[0])
	}
	if got := binary.BigEndian.Uint16(icmp[4:6]); got != 0x1234 {
		t.Fatalf("id = %#x", got)
	}
	if got := binary.BigEndian.Uint16(icmp[6:8]); got != 7 {
		t.Fatalf("seq = %d", got)
	}
	if string(icmp[8:]) != "pingdata" {
		t.Fatalf("payload = %q", icmp[8:])
	}
	if pktkit.Checksum(icmp) != 0 {
		t.Fatalf("ICMP checksum invalid: %#x", pktkit.Checksum(icmp))
	}
}

func TestBuildICMPv6Reply(t *testing.T) {
	src := netip.MustParseAddr("fd00::5")
	dst := netip.MustParseAddr("fd00::9")
	payload := []byte("v6ping!")
	icmp := make([]byte, 8+len(payload))
	icmp[0] = 128 // echo request
	binary.BigEndian.PutUint16(icmp[4:6], 0x00aa)
	binary.BigEndian.PutUint16(icmp[6:8], 42)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], slirp.IPv6Checksum(src.As16(), dst.As16(), 58, uint32(len(icmp)), icmp))

	hdr := make([]byte, 40)
	hdr[0] = 0x60
	binary.BigEndian.PutUint16(hdr[4:6], uint16(len(icmp)))
	hdr[6] = 58
	ss, dd := src.As16(), dst.As16()
	copy(hdr[8:24], ss[:])
	copy(hdr[24:40], dd[:])
	req := append(hdr, icmp...)

	reply := pktkit.Packet(buildICMPv6Reply(pktkit.Packet(req)))
	if reply == nil {
		t.Fatal("buildICMPv6Reply returned nil")
	}
	if reply.Version() != 6 {
		t.Fatalf("reply version = %d", reply.Version())
	}
	if reply.IPv6SrcAddr() != dst || reply.IPv6DstAddr() != src {
		t.Fatalf("addresses not reversed: src=%s dst=%s", reply.IPv6SrcAddr(), reply.IPv6DstAddr())
	}
	ricmp := reply.IPv6Payload()
	if ricmp[0] != 129 {
		t.Fatalf("ICMPv6 type = %d, want 129", ricmp[0])
	}
	if got := binary.BigEndian.Uint16(ricmp[6:8]); got != 42 {
		t.Fatalf("seq = %d", got)
	}
	// recompute checksum over zeroed field
	zeroed := append([]byte{}, ricmp...)
	binary.BigEndian.PutUint16(zeroed[2:4], 0)
	got := slirp.IPv6Checksum(reply.IPv6SrcAddr().As16(), reply.IPv6DstAddr().As16(), 58, uint32(len(zeroed)), zeroed)
	if want := binary.BigEndian.Uint16(ricmp[2:4]); got != want {
		t.Fatalf("ICMPv6 checksum = %#x, want %#x", got, want)
	}
}

// makeTCP builds an IPv4 packet carrying a raw TCP segment.
func makeTCP(src, dst netip.Addr, seg *vtcp.Segment) pktkit.Packet {
	body := seg.Marshal()
	hdr := make([]byte, 20)
	hdr[0] = 0x45
	binary.BigEndian.PutUint16(hdr[2:4], uint16(20+len(body)))
	hdr[9] = 6
	s4, d4 := src.As4(), dst.As4()
	copy(hdr[12:16], s4[:])
	copy(hdr[16:20], d4[:])
	binary.BigEndian.PutUint16(hdr[10:12], slirp.IPChecksum(hdr))
	binary.BigEndian.PutUint16(body[16:18], 0)
	binary.BigEndian.PutUint16(body[16:18], slirp.TCPChecksum(s4[:], d4[:], body, nil))
	return append(hdr, body...)
}

func TestBuildRST_SYN(t *testing.T) {
	src := netip.MustParseAddr("10.0.0.5")
	dst := netip.MustParseAddr("10.0.0.9")
	syn := &vtcp.Segment{SrcPort: 50000, DstPort: 80, Seq: 1000, Flags: vtcp.FlagSYN, Window: 65535}
	req := makeTCP(src, dst, syn)

	rst := buildRST(req)
	if rst == nil {
		t.Fatal("buildRST returned nil")
	}
	body := rst[20:]
	if rst[0]>>4 != 4 {
		t.Fatalf("version = %d", rst[0]>>4)
	}
	if got := netip.AddrFrom4([4]byte(rst[12:16])); got != dst {
		t.Fatalf("src = %s", got)
	}
	if got := netip.AddrFrom4([4]byte(rst[16:20])); got != src {
		t.Fatalf("dst = %s", got)
	}
	if flags := body[13]; flags != vtcp.FlagRST|vtcp.FlagACK {
		t.Fatalf("flags = %#x, want RST|ACK", flags)
	}
	if got := binary.BigEndian.Uint16(body[0:2]); got != 80 {
		t.Fatalf("src port = %d", got)
	}
	if got := binary.BigEndian.Uint16(body[2:4]); got != 50000 {
		t.Fatalf("dst port = %d", got)
	}
	if got := binary.BigEndian.Uint32(body[4:8]); got != 0 {
		t.Fatalf("seq = %d, want 0", got)
	}
	if got := binary.BigEndian.Uint32(body[8:12]); got != 1001 {
		t.Fatalf("ack = %d, want 1001", got)
	}
	zeroed := append([]byte{}, body...)
	binary.BigEndian.PutUint16(zeroed[16:18], 0)
	s4, d4 := dst.As4(), src.As4()
	got := slirp.TCPChecksum(s4[:], d4[:], zeroed, nil)
	if want := binary.BigEndian.Uint16(body[16:18]); got != want {
		t.Fatalf("TCP checksum = %#x, want %#x", got, want)
	}
}

func TestBuildRST_ACK(t *testing.T) {
	src := netip.MustParseAddr("10.0.0.5")
	dst := netip.MustParseAddr("10.0.0.9")
	ack := &vtcp.Segment{SrcPort: 50000, DstPort: 80, Seq: 5000, Ack: 777, Flags: vtcp.FlagACK, Window: 65535}
	req := makeTCP(src, dst, ack)

	rst := buildRST(req)
	if rst == nil {
		t.Fatal("buildRST returned nil")
	}
	body := rst[20:]
	if flags := body[13]; flags != vtcp.FlagRST {
		t.Fatalf("flags = %#x, want bare RST", flags)
	}
	if got := binary.BigEndian.Uint32(body[4:8]); got != 777 {
		t.Fatalf("seq = %d, want ack echo 777", got)
	}
}

func TestHandleInboundICMPDispatch(t *testing.T) {
	// Echo request addressed to us must be claimed.
	req := makeICMPv4Echo(netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr(LocalIP()), 1, 1, "x")
	if !handleInbound(req) {
		t.Fatal("handleInbound did not claim echo request")
	}
	// Non-echo ICMP must pass through (not claimed).
	other := makeICMPv4Echo(netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr(LocalIP()), 1, 1, "x")
	other[20] = 3 // destination unreachable
	if handleInbound(other) {
		t.Fatal("handleInbound claimed non-echo ICMP")
	}
	// Packet not addressed to us must pass through.
	away := makeICMPv4Echo(netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("10.0.0.6"), 1, 1, "x")
	if handleInbound(away) {
		t.Fatal("handleInbound claimed packet for another address")
	}
}

func TestListenUDP(t *testing.T) {
	pc, err := ListenUDP(33333)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	// Craft an inbound UDP datagram to our local port.
	src := netip.MustParseAddr("10.0.0.5")
	dst := netip.MustParseAddr(LocalIP())
	payload := []byte("hello-udp")
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], 1111)
	binary.BigEndian.PutUint16(udp[2:4], 33333)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)

	hdr := make([]byte, 20)
	hdr[0] = 0x45
	binary.BigEndian.PutUint16(hdr[2:4], uint16(20+len(udp)))
	hdr[9] = 17
	s4, d4 := src.As4(), dst.As4()
	copy(hdr[12:16], s4[:])
	copy(hdr[16:20], d4[:])
	binary.BigEndian.PutUint16(hdr[10:12], slirp.IPChecksum(hdr))
	binary.BigEndian.PutUint16(udp[6:8], 0)
	binary.BigEndian.PutUint16(udp[6:8], slirp.UDPChecksum(s4[:], d4[:], udp, payload))
	pkt := append(hdr, udp...)

	if !handleInbound(pktkit.Packet(pkt)) {
		t.Fatal("handleInbound did not claim bound UDP")
	}

	buf := make([]byte, 256)
	pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello-udp" {
		t.Fatalf("payload = %q", buf[:n])
	}
	ua, ok := addr.(*net.UDPAddr)
	if !ok || ua.Port != 1111 || !ua.IP.Equal(net.IP(src.AsSlice())) {
		t.Fatalf("addr = %v", addr)
	}

	// WriteTo must produce a valid datagram and route without error.
	if n, err := pc.WriteTo([]byte("reply"), &net.UDPAddr{IP: net.IP(src.AsSlice()), Port: 1111}); err != nil || n != 5 {
		t.Fatalf("WriteTo: n=%d err=%v", n, err)
	}
}

func TestHairpinTCP(t *testing.T) {
	addr := LocalIP() + ":18080"
	ln, err := softTun.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := softTun.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("hairpin dial: %v", err)
	}
	defer conn.Close()

	// Server accept.
	sconn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer sconn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := sconn.Read(buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("got %q", buf)
	}
}

func TestHairpinRefused(t *testing.T) {
	addr := LocalIP() + ":1" // closed port
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := softTun.DialContext(ctx, "tcp", addr)
	if err == nil {
		// vtcp.Connect returns nil when the RST aborts SYN-SENT (it closes
		// the established channel); the conn is then already closed. Assert
		// the abort effect: reads must EOF immediately instead of blocking.
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buf := make([]byte, 16)
		_, rerr := conn.Read(buf)
		conn.Close()
		if rerr != io.EOF {
			t.Fatalf("refused conn not aborted by RST: read err=%v", rerr)
		}
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("hairpin refused too slow: %s", elapsed)
	}
}
