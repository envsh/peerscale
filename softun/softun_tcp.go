package softun

import (
	"encoding/binary"
	"log"
	"net/netip"
	"sync"
	"time"

	"github.com/KarpelesLab/pktkit"
	"github.com/KarpelesLab/pktkit/slirp"
	"github.com/KarpelesLab/pktkit/vtcp"
)

// synKey identifies a TCP connection being established. It is derived from
// the inbound SYN as (remote, remotePort, localPort); the outbound SYN-ACK
// carries the reverse addresses so both sides resolve to the same key.
type synKey struct {
	remote     netip.Addr
	remotePort uint16
	localPort  uint16
}

var (
	synMu   sync.Mutex
	synPend = make(map[synKey]time.Time)
	synTTL  = 30 * time.Second
)

func setSynPending(k synKey) {
	synMu.Lock()
	synPend[k] = time.Now()
	synMu.Unlock()
}

// takeSynPending reports whether the key is still pending and removes it.
func takeSynPending(k synKey) bool {
	synMu.Lock()
	_, ok := synPend[k]
	if ok {
		delete(synPend, k)
	}
	synMu.Unlock()
	return ok
}

// reapSynPending drops stale pending markers whose handshake never completed
// (e.g. the SYN-ACK was lost in transit). Called periodically by the reaper.
func reapSynPending(now time.Time) int {
	synMu.Lock()
	n := 0
	for k, at := range synPend {
		if now.Sub(at) > synTTL {
			delete(synPend, k)
			n++
		}
	}
	synMu.Unlock()
	return n
}

// synKeyForPacket derives the pending key from an inbound SYN: the remote
// endpoint is the packet source.
func synKeyForPacket(pkt pktkit.Packet) (synKey, bool) {
	pl := pkt.Payload()
	if len(pl) < 4 {
		return synKey{}, false
	}
	return synKey{
		remote:     pkt.SrcAddr(),
		remotePort: binary.BigEndian.Uint16(pl[0:2]),
		localPort:  binary.BigEndian.Uint16(pl[2:4]),
	}, true
}

// synAckKeyFromPacket derives the pending key from an outbound SYN-ACK: the
// remote endpoint is the packet destination, and the local port is the source
// port of the reply.
func synAckKeyFromPacket(pkt pktkit.Packet) (synKey, bool) {
	pl := pkt.Payload()
	if len(pl) < 4 {
		return synKey{}, false
	}
	return synKey{
		remote:     pkt.DstAddr(),
		remotePort: binary.BigEndian.Uint16(pl[2:4]),
		localPort:  binary.BigEndian.Uint16(pl[0:2]),
	}, true
}

func tcpFlags(pkt pktkit.Packet) (uint8, bool) {
	pl := pkt.Payload()
	if len(pl) < 14 {
		return 0, false
	}
	return pl[13], true
}

func isSynOnly(pkt pktkit.Packet) bool {
	flags, ok := tcpFlags(pkt)
	return ok && flags&vtcp.FlagSYN != 0 && flags&vtcp.FlagACK == 0
}

// clearSynPendingForPacket drops the pending marker for an outbound SYN-ACK,
// signalling that the local stack accepted the connection. It is called from
// routeWrite, so it runs synchronously inside softTun.Send.
func clearSynPendingForPacket(pkt pktkit.Packet) {
	if pkt.IPProtocol() != pktkit.ProtocolTCP {
		return
	}
	flags, ok := tcpFlags(pkt)
	if !ok || flags&(vtcp.FlagSYN|vtcp.FlagACK) != vtcp.FlagSYN|vtcp.FlagACK {
		return
	}
	if k, ok := synAckKeyFromPacket(pkt); ok {
		takeSynPending(k)
	}
}

// handleInbound intercepts packets addressed to this node that the underlying
// vclient stack cannot serve (ICMP echo, UDP listeners, refused TCP SYNs).
// It reports whether the packet was consumed (so the caller should not forward
// it to the stack).
func handleInbound(pkt pktkit.Packet) bool {
	if !pkt.IsValid() || !isLocalAddr(pkt.DstAddr()) {
		return false
	}
	switch pkt.IPProtocol() {
	case pktkit.ProtocolICMP, pktkit.ProtocolICMPv6:
		return handleInboundICMP(pkt)
	case pktkit.ProtocolUDP:
		return handleInboundUDP(pkt)
	case pktkit.ProtocolTCP:
		return handleInboundTCP(pkt)
	}
	return false
}

// handleInboundTCP sends RST for SYNs to ports the local stack refuses.
// softTun.Send is synchronous: the acceptor's SYN-ACK is emitted through
// routeWrite before Send returns, clearing the pending marker. A still-pending
// marker therefore means the port is closed (or backlog full) and we RST.
func handleInboundTCP(pkt pktkit.Packet) bool {
	if !isSynOnly(pkt) {
		return false
	}
	k, ok := synKeyForPacket(pkt)
	if !ok {
		return false
	}
	ensureLoPortMapPort(k.localPort)
	setSynPending(k)
	softTun.Send(pkt)
	if takeSynPending(k) {
		if rst := buildRST(pkt); rst != nil {
			if err := routeWrite(pktkit.Packet(rst)); err != nil {
				log.Printf("[softun] send RST: %v", err)
			}
		}
	}
	return true
}

// hairpin loops packets addressed to this node back into the stack. A SYN to
// a closed local port is answered with an RST looped back to the dialer.
func hairpin(pkt pktkit.Packet) error {
	if pkt.IPProtocol() == pktkit.ProtocolTCP && isSynOnly(pkt) {
		if k, ok := synKeyForPacket(pkt); ok {
			ensureLoPortMapPort(k.localPort)
			setSynPending(k)
			softTun.Send(pkt)
			if takeSynPending(k) {
				if rst := buildRST(pkt); rst != nil {
					if err := softTun.Send(pktkit.Packet(rst)); err != nil {
						log.Printf("[softun] hairpin RST: %v", err)
					}
				}
			}
			return nil
		}
	}
	return softTun.Send(pkt)
}

// buildRST constructs a TCP RST replying to req (a full IP packet). Ports and
// addresses are reversed. For ACK-carrying segments a bare RST is sent
// (RFC 5961); otherwise RST|ACK acking the consumed sequence space.
func buildRST(req pktkit.Packet) []byte {
	pl := req.Payload()
	if len(pl) < 20 {
		return nil
	}
	seg, err := vtcp.ParseSegment(pl)
	if err != nil {
		log.Printf("[softun] buildRST parse: %v", err)
		return nil
	}
	reply := &vtcp.Segment{SrcPort: seg.DstPort, DstPort: seg.SrcPort, Flags: vtcp.FlagRST}
	if seg.Flags&vtcp.FlagACK != 0 {
		// RFC 5961: bare RST with SEQ = SEG.ACK.
		reply.Seq = seg.Ack
	} else {
		// RFC 9293 §3.10.7.2/§3.10.7.3: RST|ACK with ACK = SEG.SEQ + SEG.LEN
		// so the SYN is acknowledged and the remote aborts in SYN-SENT.
		reply.Ack = seg.Seq + seg.SegLen()
		reply.Flags = vtcp.FlagRST | vtcp.FlagACK
	}
	body := reply.Marshal()
	switch req.Version() {
	case 4:
		return wrapIPv4(req.IPv4DstAddr(), req.IPv4SrcAddr(), uint8(pktkit.ProtocolTCP), body)
	case 6:
		return wrapIPv6(req.IPv6DstAddr(), req.IPv6SrcAddr(), uint8(pktkit.ProtocolTCP), body)
	}
	log.Printf("[softun] buildRST: unsupported IP version %d", req.Version())
	return nil
}

// wrapIPv4 assembles an IPv4 packet around an L4 body, computing the IP and
// (for TCP/UDP) L4 checksums.
func wrapIPv4(srcIP, dstIP netip.Addr, proto uint8, l4 []byte) []byte {
	total := 20 + len(l4)
	hdr := make([]byte, 20)
	hdr[0] = 0x45
	binary.BigEndian.PutUint16(hdr[2:4], uint16(total))
	hdr[8] = 64
	hdr[9] = proto
	s4, d4 := srcIP.As4(), dstIP.As4()
	copy(hdr[12:16], s4[:])
	copy(hdr[16:20], d4[:])
	binary.BigEndian.PutUint16(hdr[10:12], slirp.IPChecksum(hdr))
	fillChecksum4(s4, d4, proto, l4)
	out := make([]byte, total)
	copy(out, hdr)
	copy(out[20:], l4)
	return out
}

func fillChecksum4(s4, d4 [4]byte, proto uint8, l4 []byte) {
	switch proto {
	case uint8(pktkit.ProtocolTCP):
		if len(l4) >= 18 {
			binary.BigEndian.PutUint16(l4[16:18], 0)
			binary.BigEndian.PutUint16(l4[16:18], slirp.TCPChecksum(s4[:], d4[:], l4, nil))
		}
	case uint8(pktkit.ProtocolUDP):
		if len(l4) >= 8 {
			binary.BigEndian.PutUint16(l4[6:8], 0)
			binary.BigEndian.PutUint16(l4[6:8], slirp.UDPChecksum(s4[:], d4[:], l4, nil))
		}
	}
}

// wrapIPv6 assembles an IPv6 packet around an L4 body, computing the L4
// checksum for TCP/UDP via the IPv6 pseudo-header.
func wrapIPv6(srcIP, dstIP netip.Addr, proto uint8, l4 []byte) []byte {
	total := 40 + len(l4)
	hdr := make([]byte, 40)
	hdr[0] = 0x60
	binary.BigEndian.PutUint16(hdr[4:6], uint16(len(l4)))
	hdr[6] = proto
	hdr[7] = 64
	s6, d6 := srcIP.As16(), dstIP.As16()
	copy(hdr[8:24], s6[:])
	copy(hdr[24:40], d6[:])
	fillChecksum6(s6, d6, proto, l4)
	out := make([]byte, total)
	copy(out, hdr)
	copy(out[40:], l4)
	return out
}

func fillChecksum6(s6, d6 [16]byte, proto uint8, l4 []byte) {
	switch proto {
	case uint8(pktkit.ProtocolTCP):
		if len(l4) >= 18 {
			binary.BigEndian.PutUint16(l4[16:18], 0)
			binary.BigEndian.PutUint16(l4[16:18], slirp.IPv6Checksum(s6, d6, proto, uint32(len(l4)), l4))
		}
	case uint8(pktkit.ProtocolUDP):
		if len(l4) >= 8 {
			binary.BigEndian.PutUint16(l4[6:8], 0)
			binary.BigEndian.PutUint16(l4[6:8], slirp.IPv6Checksum(s6, d6, proto, uint32(len(l4)), l4))
		}
	}
}
