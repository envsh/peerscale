package fbvirtun

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"fedbridge/vtcp"

	"github.com/envsh/libp2px/p2put"
	"github.com/envsh/libp2px/pbtunnel"
)

type tcpKey struct {
	srcIP   [4]byte
	srcPort uint16
	dstIP   [4]byte
	dstPort uint16
}

// seen connections with: ss -ant|grep EST|grep 9339
type tcpBridge struct {
	vc                *vtcp.Conn
	remote            net.Conn
	establishedLogged bool
	connid            int64
}

var natconnid int64 = 10000
var tcpConns sync.Map

func tcpKeyFrom4(pkt []byte, ihl int, srcIP, dstIP [4]byte) tcpKey {
	return tcpKey{
		srcIP:   srcIP,
		dstIP:   dstIP,
		srcPort: binary.BigEndian.Uint16(pkt[ihl:]),
		dstPort: binary.BigEndian.Uint16(pkt[ihl+2:]),
	}
}

func handleTCP4(pkt []byte, ihl int, srcIP, dstIP [4]byte) {
	tcp := pkt[ihl:]
	if len(tcp) < 20 {
		return
	}
	flags := tcp[13]
	k := tcpKeyFrom4(pkt, ihl, srcIP, dstIP)

	if v, ok := tcpConns.Load(k); ok {
		feedTCP(v.(*tcpBridge), tcp)
		return
	}

	if flags&vtcp.FlagSYN == 0 {
		sendRST4(tcp, srcIP, dstIP)
		return
	}

	bridge := newTCPBridge(tcp, srcIP, dstIP, k.srcPort, k.dstPort)
	if bridge == nil {
		sendRST4(tcp, srcIP, dstIP)
		return
	}
	tcpConns.Store(k, bridge)
	log.Printf("tun: TCP NAT new %s:%d → %s:%d [+]",
		net.IP(srcIP[:]).String(), k.srcPort,
		net.IP(dstIP[:]).String(), k.dstPort)
}

func handleTCP6(pkt []byte, srcIP, dstIP [16]byte) {
	tcp := pkt[40:]
	if len(tcp) < 20 {
		return
	}
	flags := tcp[13]

	var k4 struct {
		srcIP   [16]byte
		srcPort uint16
		dstIP   [16]byte
		dstPort uint16
	}
	k4.srcIP = srcIP
	k4.srcPort = binary.BigEndian.Uint16(tcp[0:2])
	k4.dstIP = dstIP
	k4.dstPort = binary.BigEndian.Uint16(tcp[2:4])

	if v, ok := tcpConns.Load(k4); ok {
		feedTCP(v.(*tcpBridge), tcp)
		return
	}

	if flags&vtcp.FlagSYN == 0 {
		sendRST6(tcp, srcIP, dstIP)
		return
	}

	bridge := newTCPBridge6(tcp, srcIP, dstIP, k4.srcPort, k4.dstPort)
	if bridge == nil {
		sendRST6(tcp, srcIP, dstIP)
		return
	}
	tcpConns.Store(k4, bridge)
	log.Printf("tun: TCP NAT new [%s]:%d → [%s]:%d [+]",
		net.IP(srcIP[:]).String(), k4.srcPort,
		net.IP(dstIP[:]).String(), k4.dstPort)
}

func feedTCP(bridge *tcpBridge, tcp []byte) {
	seg, err := vtcp.ParseSegment(tcp)
	if err != nil {
		log.Printf("tun: TCP -> %s %s [+]",
			bridge.remote.RemoteAddr().String(), err.Error())
		return
	}
	pkts := bridge.vc.HandleSegment(seg)
	bridge.vc.Flush(pkts)
	if bridge.vc.State() == vtcp.StateEstablished && !bridge.establishedLogged {
		bridge.establishedLogged = true
		DDLog.Printf("tun: TCP ESTAB %s ↔ %s [+]",
			bridge.vc.LocalAddr(), bridge.vc.RemoteAddr())
	}
	if bridge.vc.State() == vtcp.StateClosed {
		if seg.HasFlag(vtcp.FlagRST) {
			DDLog.Printf("tun: TCP %s → %s RST seq=%d ack=%d [+]",
				bridge.vc.LocalAddr(), bridge.vc.RemoteAddr(),
				seg.Seq, seg.Ack)
		} else {
			DDLog.Printf("tun: TCP %s ↔ %s CLOSED [+]",
				bridge.vc.LocalAddr(), bridge.vc.RemoteAddr())
		}
	}
}

var (
	peerips   = map[string]string{} // ip => peerid
	peeripsMu sync.Mutex
)

// return empty for default
func peeridByConnIP(ipport string) string {
	rawIP, _, err := net.SplitHostPort(ipport)
	if err != nil {
		return ""
	}
	if rawIP == "127.0.0.1" {
		return ""
	}

	peeripsMu.Lock()
	defer peeripsMu.Unlock()

	if id, ok := peerips[rawIP]; ok {
		return id
	}

	ids := p2put.GetClusterPeers()
	sort.Strings(ids)
	for _, id := range ids {
		hostPart := StringToHostPart(id)
		mappedIP := VlanPfx + strconv.Itoa(hostPart)
		peerips[mappedIP] = id
	}
	return peerips[rawIP]
}

func newTCPBridge(tcp []byte, srcIP, dstIP [4]byte, srcPort, dstPort uint16) *tcpBridge {
	seg, err := vtcp.ParseSegment(tcp)
	if err != nil {
		log.Printf("tun: TCP NAT new [%s]:%d → [%s]:%d <x> %s [+]",
			net.IP(srcIP[:]).String(), srcPort,
			net.IP(dstIP[:]).String(), dstPort, err.Error())
		return nil
	}

	dstAddr := net.JoinHostPort(net.IP(dstIP[:]).String(), itoaU16(dstPort))
	if strings.HasPrefix(dstAddr, LocalPeerIP+":") {
		// self good goon
	} else if id := peeridByConnIP(dstAddr); id != "" {
		dstAddr = net.JoinHostPort(id, itoaU16(dstPort))
	} else {
		DDLog.Printf("no route to %s myip %s", dstAddr, LocalPeerIP)
		return nil
	}
	log.Printf("tun: TCP NAT new [%s]:%d → [%s]:%d <x> %s [+]",
		net.IP(srcIP[:]).String(), srcPort,
		net.IP(dstIP[:]).String(), dstPort, dstAddr)

	remote_, err := pbtunnel.Dial(dstAddr)
	remote := &pbtunnel.P2PConn{remote_}
	// remote, err := net.Dial("tcp", dstAddr)
	if err != nil {
		log.Println(err)
		return nil
	}

	localAddr := &net.TCPAddr{IP: net.IP(dstIP[:]).To4(), Port: int(dstPort)}
	remoteAddr := &net.TCPAddr{IP: net.IP(srcIP[:]).To4(), Port: int(srcPort)}

	vc := vtcp.NewConn(vtcp.ConnConfig{
		LocalPort:  dstPort,
		RemotePort: srcPort,
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
		Writer: func(tcpSeg []byte) error {
			return writeTun(buildPacket4(dstIP, srcIP, tcpSeg))
		},
		MSS:       1460,
		Keepalive: true,
	})

	bridge := &tcpBridge{vc: vc, remote: remote}
	bridge.connid = atomic.AddInt64(&natconnid, 1)
	vc.Flush(vc.AcceptSYN(seg))
	bridge.startBridge()
	return bridge
}

func newTCPBridge6(tcp []byte, srcIP, dstIP [16]byte, srcPort, dstPort uint16) *tcpBridge {
	seg, err := vtcp.ParseSegment(tcp)
	if err != nil {
		log.Printf("tun: TCP NAT new [%s]:%d → [%s]:%d <x> %s [+]",
			net.IP(srcIP[:]).String(), srcPort,
			net.IP(dstIP[:]).String(), dstPort, err.Error())
		return nil
	}

	log.Printf("tun: TCP NAT new [%s]:%d → [%s]:%d <x> %s [+]",
		net.IP(srcIP[:]).String(), srcPort,
		net.IP(dstIP[:]).String(), dstPort, "todo dail peer dst 56789")

	remote, err := net.Dial("tcp6", net.JoinHostPort(net.IP(dstIP[:]).String(), itoaU16(dstPort)))
	if err != nil {
		return nil
	}

	localAddr := &net.TCPAddr{IP: net.IP(dstIP[:]), Port: int(dstPort)}
	remoteAddr := &net.TCPAddr{IP: net.IP(srcIP[:]), Port: int(srcPort)}

	vc := vtcp.NewConn(vtcp.ConnConfig{
		LocalPort:  dstPort,
		RemotePort: srcPort,
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
		Writer: func(tcpSeg []byte) error {
			return writeTun(buildPacket6(dstIP, srcIP, tcpSeg))
		},
		MSS:       1440,
		Keepalive: true,
	})

	bridge := &tcpBridge{vc: vc, remote: remote}
	vc.Flush(vc.AcceptSYN(seg))
	bridge.startBridge()
	return bridge
}

func (b *tcpBridge) startBridge() {
	// for only one close log per conn
	closed := false
	closeFunc := func(reason string) {
		if closed {
			return
		}
		closed = true
		log.Printf("tun: TCP %s → %s %s [+]",
			b.vc.LocalAddr(), b.vc.RemoteAddr(), reason)
	}
	go func() {
		io.Copy(b.vc, b.remote)
		closeFunc("remote close")
		b.vc.Close()
	}()
	go func() {
		io.Copy(b.remote, b.vc)
		closeFunc("local FIN")
		if tc, ok := b.remote.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
}

func sendRST4(tcp []byte, srcIP, dstIP [4]byte) {
	flags := tcp[13]
	var rstSeg vtcp.Segment
	if flags&vtcp.FlagACK != 0 {
		rstSeg = vtcp.Segment{
			SrcPort: binary.BigEndian.Uint16(tcp[2:4]),
			DstPort: binary.BigEndian.Uint16(tcp[0:2]),
			Seq:     binary.BigEndian.Uint32(tcp[8:12]),
			Flags:   vtcp.FlagRST,
		}
	} else {
		dataOff := int(tcp[12]>>4) * 4
		dataLen := uint32(len(tcp) - dataOff)
		if tcp[13]&0x01 != 0 {
			dataLen++
		}
		rstSeg = vtcp.Segment{
			SrcPort: binary.BigEndian.Uint16(tcp[2:4]),
			DstPort: binary.BigEndian.Uint16(tcp[0:2]),
			Ack:     binary.BigEndian.Uint32(tcp[4:8]) + dataLen,
			Flags:   vtcp.FlagRST | vtcp.FlagACK,
		}
	}
	pkt := buildPacket4(dstIP, srcIP, rstSeg.Marshal())
	writeTun(pkt)
}

func sendRST6(tcp []byte, srcIP, dstIP [16]byte) {
	flags := tcp[13]
	var rstSeg vtcp.Segment
	if flags&vtcp.FlagACK != 0 {
		rstSeg = vtcp.Segment{
			SrcPort: binary.BigEndian.Uint16(tcp[2:4]),
			DstPort: binary.BigEndian.Uint16(tcp[0:2]),
			Seq:     binary.BigEndian.Uint32(tcp[8:12]),
			Flags:   vtcp.FlagRST,
		}
	} else {
		dataOff := int(tcp[12]>>4) * 4
		dataLen := uint32(len(tcp) - dataOff)
		if tcp[13]&0x01 != 0 {
			dataLen++
		}
		rstSeg = vtcp.Segment{
			SrcPort: binary.BigEndian.Uint16(tcp[2:4]),
			DstPort: binary.BigEndian.Uint16(tcp[0:2]),
			Ack:     binary.BigEndian.Uint32(tcp[4:8]) + dataLen,
			Flags:   vtcp.FlagRST | vtcp.FlagACK,
		}
	}
	pkt := buildPacket6(dstIP, srcIP, rstSeg.Marshal())
	writeTun(pkt)
}

func itoaU16(v uint16) string {
	return strconv.FormatUint(uint64(v), 10)
}

func tcpCleanup() {
	tcpConns.Range(func(k, v any) bool {
		bridge, ok := v.(*tcpBridge)
		if !ok {
			tcpConns.Delete(k)
			return true
		}
		if bridge.vc.State() == vtcp.StateClosed {
			bridge.remote.Close()
			tcpConns.Delete(k)
		}
		return true
	})
}

// --- IP packet builders (IPv4 / IPv6) ---

func buildPacket4(srcIP, dstIP [4]byte, tcpSeg []byte) []byte {
	ihl := 20
	totalLen := ihl + len(tcpSeg)

	ip := make([]byte, ihl)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])
	binary.BigEndian.PutUint16(ip[10:12], 0)
	binary.BigEndian.PutUint16(ip[10:12], onesComplementSum(ip))

	tcpCopy := make([]byte, len(tcpSeg))
	copy(tcpCopy, tcpSeg)
	binary.BigEndian.PutUint16(tcpCopy[16:18], 0)
	tcpLen := uint16(len(tcpCopy))
	psum := pseudoChecksum(srcIP[:], dstIP[:], 6, tcpLen)
	cs := onesComplementSumFold(tcpCopy, psum)
	binary.BigEndian.PutUint16(tcpCopy[16:18], cs)

	pkt := make([]byte, ihl+len(tcpCopy))
	copy(pkt, ip)
	copy(pkt[ihl:], tcpCopy)
	return pkt
}

func buildPacket6(srcIP, dstIP [16]byte, tcpSeg []byte) []byte {
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(tcpSeg)))
	ip[6] = 6
	ip[7] = 64
	copy(ip[8:24], srcIP[:])
	copy(ip[24:40], dstIP[:])

	tcpCopy := make([]byte, len(tcpSeg))
	copy(tcpCopy, tcpSeg)
	binary.BigEndian.PutUint16(tcpCopy[16:18], 0)
	tcpLen := uint16(len(tcpCopy))
	psum := pseudoChecksum6(srcIP[:], dstIP[:], 6, tcpLen)
	cs := onesComplementSumFold(tcpCopy, psum)
	binary.BigEndian.PutUint16(tcpCopy[16:18], cs)

	pkt := make([]byte, 40+len(tcpCopy))
	copy(pkt, ip)
	copy(pkt[40:], tcpCopy)
	return pkt
}

func writeTun(pkt []byte) error {
	if Tunov == nil {
		return nil
	}
	buf := make([]byte, tunBufSize)
	n := copy(buf[tunOffset:], pkt)
	_, err := Tunov.Write([][]byte{buf[:tunOffset+n]}, tunOffset)
	if err != nil {
		log.Printf("tun: write error: %v", err)
	}
	return err
}
