package fbvirtun

import (
	"context"
	"errors"
	"log"
	"net"
	"strings"
	"time"

	"github.com/envsh/libp2px/pbtunnel"
)

func handleICMP4(pkt []byte, ihl int, bufs [][]byte, n int) bool {
	icmp := pkt[ihl:]
	if len(icmp) < 8 || icmp[0] != 8 {
		return false
	}

	dstStr := net.IP(pkt[16:20]).String()
	pid := peeridByConnIP(net.JoinHostPort(dstStr, "0"))
	if pid == "" {
		writeICMPDestUnreach4(pkt, ihl, 1)
		Tunov.Write(bufs[:1], tunOffset)
		log.Printf("tun: ICMP Dest Unreach v4 %s → %s len=%d [+]",
			net.IP(pkt[12:16]).String(), net.IP(pkt[16:20]).String(), n)
		return true
	}

	log.Printf("tun: ICMP v4 Dial %s ...", pid+":1")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stm, err := pbtunnel.Dial(pid+":1", ctx)
	if stm != nil {
		stm.Close()
	}
	log.Println(pid+":1", err)

	if err == nil {
		writeICMPEchoReply4(pkt, ihl)
	} else if errors.Is(err, context.DeadlineExceeded) {
		writeICMPTimeExceed4(pkt, ihl, 1)
	} else if isProtocolRefused(err) {
		log.Printf("tun: ICMP v4 Dial refused: %v", err)
		writeICMPDestUnreach4(pkt, ihl, 3)
	} else {
		log.Printf("tun: ICMP v4 Dial error: %v", err)
		writeICMPDestUnreach4(pkt, ihl, 1)
	}
	Tunov.Write(bufs[:1], tunOffset)
	log.Printf("tun: ICMP v4 %s → %s len=%d [+]",
		net.IP(pkt[12:16]).String(), net.IP(pkt[16:20]).String(), n)
	return true
}

func handleICMP6(pkt []byte, bufs [][]byte, n int) bool {
	if len(pkt) < 48 || pkt[40] != 128 {
		return false
	}

	dstStr := net.IP(pkt[24:40]).String()
	pid := peeridByConnIP(net.JoinHostPort(dstStr, "0"))
	if pid == "" {
		writeICMPDestUnreach6(pkt, 3)
		Tunov.Write(bufs[:1], tunOffset)
		log.Printf("tun: ICMPv6 Dest Unreach %s → %s len=%d [+]",
			net.IP(pkt[8:24]).String(), net.IP(pkt[24:40]).String(), n)
		return true
	}

	log.Printf("tun: ICMPv6 Dial %s", pid+":1")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stm, err := pbtunnel.Dial(pid+":1", ctx)
	if stm != nil {
		stm.Close()
	}

	if err == nil {
		writeICMPEchoReply6(pkt)
	} else if errors.Is(err, context.DeadlineExceeded) {
		writeICMPTimeExceed6(pkt, 1)
	} else if isProtocolRefused(err) {
		log.Printf("tun: ICMPv6 Dial refused: %v", err)
		writeICMPDestUnreach6(pkt, 4)
	} else {
		log.Printf("tun: ICMPv6 Dial error: %v", err)
		writeICMPDestUnreach6(pkt, 3)
	}
	Tunov.Write(bufs[:1], tunOffset)
	log.Printf("tun: ICMPv6 %s → %s len=%d [+]",
		net.IP(pkt[8:24]).String(), net.IP(pkt[24:40]).String(), n)
	return true
}

// ── ICMPv4 packet writers ──

func writeICMPEchoReply4(pkt []byte, ihl int) {
	tmp := make([]byte, 4)
	copy(tmp, pkt[12:16])
	copy(pkt[12:16], pkt[16:20])
	copy(pkt[16:20], tmp)

	icmp := pkt[ihl:]
	icmp[0] = 0
	icmp[1] = 0
	icmp[2], icmp[3] = 0, 0
	csum := onesComplementSum(icmp)
	icmp[2] = byte(csum >> 8)
	icmp[3] = byte(csum & 0xFF)
	fixIPChecksum(pkt)
}

func writeICMPDestUnreach4(pkt []byte, ihl int, code byte) {
	origHdr := make([]byte, ihl)
	copy(origHdr, pkt[:ihl])
	origIcmp := make([]byte, 8)
	copy(origIcmp, pkt[ihl:ihl+8])

	swap4(pkt)
	totalLen := ihl + 8 + ihl + 8
	pkt[2] = byte(totalLen >> 8)
	pkt[3] = byte(totalLen)

	pkt[ihl+0] = 3
	pkt[ihl+1] = code
	pkt[ihl+2] = 0
	pkt[ihl+3] = 0
	pkt[ihl+4] = 0
	pkt[ihl+5] = 0
	pkt[ihl+6] = 0
	pkt[ihl+7] = 0

	copy(pkt[ihl+8:], origHdr)
	copy(pkt[ihl+8+ihl:], origIcmp)

	icmpLen := 8 + ihl + 8
	icmp := pkt[ihl : ihl+icmpLen]
	pkt[ihl+2], pkt[ihl+3] = 0, 0
	csum := onesComplementSum(icmp)
	pkt[ihl+2] = byte(csum >> 8)
	pkt[ihl+3] = byte(csum & 0xFF)
	fixIPChecksum(pkt)
}

func writeICMPTimeExceed4(pkt []byte, ihl int, code byte) {
	origHdr := make([]byte, ihl)
	copy(origHdr, pkt[:ihl])
	origIcmp := make([]byte, 8)
	copy(origIcmp, pkt[ihl:ihl+8])

	swap4(pkt)
	totalLen := ihl + 8 + ihl + 8
	pkt[2] = byte(totalLen >> 8)
	pkt[3] = byte(totalLen)

	pkt[ihl+0] = 11
	pkt[ihl+1] = code
	pkt[ihl+2] = 0
	pkt[ihl+3] = 0
	pkt[ihl+4] = 0
	pkt[ihl+5] = 0
	pkt[ihl+6] = 0
	pkt[ihl+7] = 0

	copy(pkt[ihl+8:], origHdr)
	copy(pkt[ihl+8+ihl:], origIcmp)

	icmpLen := 8 + ihl + 8
	icmp := pkt[ihl : ihl+icmpLen]
	pkt[ihl+2], pkt[ihl+3] = 0, 0
	csum := onesComplementSum(icmp)
	pkt[ihl+2] = byte(csum >> 8)
	pkt[ihl+3] = byte(csum & 0xFF)
	fixIPChecksum(pkt)
}

// ── ICMPv6 packet writers ──

func writeICMPEchoReply6(pkt []byte) {
	swap6(pkt)
	icmp := pkt[40:]
	icmp[0] = 129
	icmp[1] = 0
	icmp[2], icmp[3] = 0, 0
	psum := pseudoChecksum6(pkt[8:24], pkt[24:40], 58, uint16(len(icmp)))
	csum := onesComplementSumFold(icmp, psum)
	icmp[2] = byte(csum >> 8)
	icmp[3] = byte(csum & 0xFF)
}

func writeICMPDestUnreach6(pkt []byte, code byte) {
	origHdr := make([]byte, 40)
	copy(origHdr, pkt[:40])
	origIcmp := make([]byte, 8)
	copy(origIcmp, pkt[40:48])

	swap6(pkt)
	payLen := 8 + 40 + 8
	pkt[4] = byte(payLen >> 8)
	pkt[5] = byte(payLen)

	pkt[40+0] = 1
	pkt[40+1] = code
	pkt[40+2] = 0
	pkt[40+3] = 0
	pkt[40+4] = 0
	pkt[40+5] = 0
	pkt[40+6] = 0
	pkt[40+7] = 0

	copy(pkt[48:], origHdr)
	copy(pkt[48+40:], origIcmp)

	icmpLen := 8 + 40 + 8
	icmp := pkt[40 : 40+icmpLen]
	pkt[40+2], pkt[40+3] = 0, 0
	psum := pseudoChecksum6(pkt[8:24], pkt[24:40], 58, uint16(icmpLen))
	csum := onesComplementSumFold(icmp, psum)
	pkt[40+2] = byte(csum >> 8)
	pkt[40+3] = byte(csum & 0xFF)
}

func writeICMPTimeExceed6(pkt []byte, code byte) {
	origHdr := make([]byte, 40)
	copy(origHdr, pkt[:40])
	origIcmp := make([]byte, 8)
	copy(origIcmp, pkt[40:48])

	swap6(pkt)
	payLen := 8 + 40 + 8
	pkt[4] = byte(payLen >> 8)
	pkt[5] = byte(payLen)

	pkt[40+0] = 3
	pkt[40+1] = code
	pkt[40+2] = 0
	pkt[40+3] = 0
	pkt[40+4] = 0
	pkt[40+5] = 0
	pkt[40+6] = 0
	pkt[40+7] = 0

	copy(pkt[48:], origHdr)
	copy(pkt[48+40:], origIcmp)

	icmpLen := 8 + 40 + 8
	icmp := pkt[40 : 40+icmpLen]
	pkt[40+2], pkt[40+3] = 0, 0
	psum := pseudoChecksum6(pkt[8:24], pkt[24:40], 58, uint16(icmpLen))
	csum := onesComplementSumFold(icmp, psum)
	pkt[40+2] = byte(csum >> 8)
	pkt[40+3] = byte(csum & 0xFF)
}

// ── helpers ──

func isProtocolRefused(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "refused")
}

func swap4(pkt []byte) {
	tmp := make([]byte, 4)
	copy(tmp, pkt[12:16])
	copy(pkt[12:16], pkt[16:20])
	copy(pkt[16:20], tmp)
}

func swap6(pkt []byte) {
	tmp := make([]byte, 16)
	copy(tmp, pkt[8:24])
	copy(pkt[8:24], pkt[24:40])
	copy(pkt[24:40], tmp)
}
