package fbvirtun

import (
	"encoding/binary"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	// "github.com/envsh/libp2px/p2put"
	"github.com/envsh/libp2px/pbtunnel"
)

type udpKey4 struct {
	srcIP   [4]byte
	srcPort uint16
	dstIP   [4]byte
	dstPort uint16
}

type udpKey6 struct {
	srcIP   [16]byte
	srcPort uint16
	dstIP   [16]byte
	dstPort uint16
}

type udpFlow4 struct {
	mu         sync.Mutex
	clientIP   [4]byte
	clientPort uint16
	serverIP   [4]byte
	serverPort uint16
	conn       net.Conn
	lastUse    time.Time
}

type udpFlow6 struct {
	mu         sync.Mutex
	clientIP   [16]byte
	clientPort uint16
	serverIP   [16]byte
	serverPort uint16
	conn       net.Conn
	lastUse    time.Time
}

var udpConns4 sync.Map
var udpConns6 sync.Map

func handleUDP4(pkt []byte, ihl int, srcIP, dstIP [4]byte) {
	udp := pkt[ihl:]
	if len(udp) < 8 {
		log.Printf("invalid pktlen %v, must >=8", len(udp))
		return
	}
	srcPort := binary.BigEndian.Uint16(udp[0:2])
	dstPort := binary.BigEndian.Uint16(udp[2:4])

	k := udpKey4{srcIP, srcPort, dstIP, dstPort}
	if v, ok := udpConns4.Load(k); ok {
		f := v.(*udpFlow4)
		f.mu.Lock()
		f.lastUse = time.Now()
		f.mu.Unlock()
		f.conn.Write(udp[8:])
		return
	}

	dstAddr := net.JoinHostPort(net.IP(dstIP[:]).String(), itoaU16(dstPort))
	if strings.HasPrefix(dstAddr, LocalPeerIP+":") {
		// self good goon
	} else if id := peeridByConnIP(dstAddr); id != "" {
		dstAddr = net.JoinHostPort(id, itoaU16(dstPort))
	} else {
		DDLog.Printf("no route to %s myip %s", dstAddr, LocalPeerIP)
		return
	}

	conn, err := pbtunnel.DialUDP(dstAddr)
	// conn, err := net.Dial("udp", net.JoinHostPort(net.IP(dstIP[:]).String(), itoaU16(dstPort)))
	if err != nil {
		log.Printf("tun: UDP dial %s:%d: %v", net.IP(dstIP[:]).String(), dstPort, err)
		return
	}

	f := &udpFlow4{
		clientIP:   srcIP,
		clientPort: srcPort,
		serverIP:   dstIP,
		serverPort: dstPort,
		conn:       conn,
		lastUse:    time.Now(),
	}
	udpConns4.Store(k, f)
	go udpReadLoop4(f, k)
	_, err = conn.Write(udp[8:])
	if err != nil {
		log.Println(err)
	}
	log.Printf("tun: UDP NAT new %s:%d → %s:%d [+]",
		net.IP(srcIP[:]).String(), srcPort,
		net.IP(dstIP[:]).String(), dstPort)
}

func handleUDP6(pkt []byte, srcIP, dstIP [16]byte) {
	udp := pkt[40:]
	if len(udp) < 8 {
		return
	}
	srcPort := binary.BigEndian.Uint16(udp[0:2])
	dstPort := binary.BigEndian.Uint16(udp[2:4])

	k := udpKey6{srcIP, srcPort, dstIP, dstPort}
	if v, ok := udpConns6.Load(k); ok {
		f := v.(*udpFlow6)
		f.mu.Lock()
		f.lastUse = time.Now()
		f.mu.Unlock()
		f.conn.Write(udp[8:])
		return
	}

	conn, err := net.Dial("udp6", net.JoinHostPort(net.IP(dstIP[:]).String(), itoaU16(dstPort)))
	if err != nil {
		log.Printf("tun: UDP dial [%s]:%d: %v", net.IP(dstIP[:]).String(), dstPort, err)
		return
	}

	f := &udpFlow6{
		clientIP:   srcIP,
		clientPort: srcPort,
		serverIP:   dstIP,
		serverPort: dstPort,
		conn:       conn,
		lastUse:    time.Now(),
	}
	udpConns6.Store(k, f)
	go udpReadLoop6(f, k)
	conn.Write(udp[8:])
	log.Printf("tun: UDP NAT new [%s]:%d → [%s]:%d [+]",
		net.IP(srcIP[:]).String(), srcPort,
		net.IP(dstIP[:]).String(), dstPort)
}

func udpReadLoop4(f *udpFlow4, k udpKey4) {
	buf := make([]byte, 65507)
	for {
		f.conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		n, err := f.conn.Read(buf)
		if err != nil {
			log.Println(err, f.serverIP, f.serverPort)
			f.conn.Close()
			udpConns4.Delete(k)
			return
		}

		f.mu.Lock()
		f.lastUse = time.Now()
		f.mu.Unlock()
		udpHdr := make([]byte, 8)
		binary.BigEndian.PutUint16(udpHdr[0:2], f.serverPort)
		binary.BigEndian.PutUint16(udpHdr[2:4], f.clientPort)
		udpLen := uint16(8 + n)
		binary.BigEndian.PutUint16(udpHdr[4:6], udpLen)
		udpData := append(udpHdr, buf[:n]...)
		pkt := buildUDP4(f.serverIP, f.clientIP, udpData)
		err = writeTun(pkt)
		if err != nil {
			log.Println(err)
		}
	}
}

func udpReadLoop6(f *udpFlow6, k udpKey6) {
	buf := make([]byte, 65507)
	for {
		f.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := f.conn.Read(buf)
		if err != nil {
			f.conn.Close()
			udpConns6.Delete(k)
			return
		}
		f.mu.Lock()
		f.lastUse = time.Now()
		f.mu.Unlock()
		udpHdr := make([]byte, 8)
		binary.BigEndian.PutUint16(udpHdr[0:2], f.serverPort)
		binary.BigEndian.PutUint16(udpHdr[2:4], f.clientPort)
		udpLen := uint16(8 + n)
		binary.BigEndian.PutUint16(udpHdr[4:6], udpLen)
		udpData := append(udpHdr, buf[:n]...)
		pkt := buildUDP6(f.serverIP, f.clientIP, udpData)
		writeTun(pkt)
	}
}

func udpCleanup() {
	now := time.Now()
	udpConns4.Range(func(k, v any) bool {
		f := v.(*udpFlow4)
		f.mu.Lock()
		age := now.Sub(f.lastUse)
		f.mu.Unlock()
		if age > 60*time.Second {
			f.conn.Close()
			udpConns4.Delete(k)
		}
		return true
	})
	udpConns6.Range(func(k, v any) bool {
		f := v.(*udpFlow6)
		f.mu.Lock()
		age := now.Sub(f.lastUse)
		f.mu.Unlock()
		if age > 60*time.Second {
			f.conn.Close()
			udpConns6.Delete(k)
		}
		return true
	})
}

// --- UDP packet builders ---

func buildUDP4(srcIP, dstIP [4]byte, udpSeg []byte) []byte {
	ihl := 20
	totalLen := ihl + len(udpSeg)

	ip := make([]byte, ihl)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])
	binary.BigEndian.PutUint16(ip[10:12], 0)
	binary.BigEndian.PutUint16(ip[10:12], onesComplementSum(ip))

	udpCopy := make([]byte, len(udpSeg))
	copy(udpCopy, udpSeg)
	binary.BigEndian.PutUint16(udpCopy[6:8], 0)
	udpLen := uint16(len(udpCopy))
	psum := pseudoChecksum(srcIP[:], dstIP[:], 17, udpLen)
	cs := onesComplementSumFold(udpCopy, psum)
	binary.BigEndian.PutUint16(udpCopy[6:8], cs)

	pkt := make([]byte, ihl+len(udpCopy))
	copy(pkt, ip)
	copy(pkt[ihl:], udpCopy)
	return pkt
}

func buildUDP6(srcIP, dstIP [16]byte, udpSeg []byte) []byte {
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(udpSeg)))
	ip[6] = 17
	ip[7] = 64
	copy(ip[8:24], srcIP[:])
	copy(ip[24:40], dstIP[:])

	udpCopy := make([]byte, len(udpSeg))
	copy(udpCopy, udpSeg)
	binary.BigEndian.PutUint16(udpCopy[6:8], 0)
	udpLen := uint16(len(udpCopy))
	psum := pseudoChecksum6(srcIP[:], dstIP[:], 17, udpLen)
	cs := onesComplementSumFold(udpCopy, psum)
	binary.BigEndian.PutUint16(udpCopy[6:8], cs)

	pkt := make([]byte, 40+len(udpCopy))
	copy(pkt, ip)
	copy(pkt[40:], udpCopy)
	return pkt
}
