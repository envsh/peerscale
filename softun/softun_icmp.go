package softun

import (
	"encoding/binary"

	"github.com/KarpelesLab/pktkit"
	"github.com/KarpelesLab/pktkit/slirp"
)

// handleInboundICMP replies to ICMP echo requests addressed to this node.
// Other ICMP types are passed through (the vclient stack drops them).
func handleInboundICMP(pkt pktkit.Packet) bool {
	switch pkt.Version() {
	case 4:
		pl := pkt.IPv4Payload()
		if len(pl) < 8 || pl[0] != 8 {
			return false
		}
		if reply := buildICMPv4Reply(pkt); reply != nil {
			routeWrite(pktkit.Packet(reply))
		}
		return true
	case 6:
		pl := pkt.IPv6Payload()
		if len(pl) < 8 || pl[0] != 128 {
			return false
		}
		if reply := buildICMPv6Reply(pkt); reply != nil {
			routeWrite(pktkit.Packet(reply))
		}
		return true
	}
	return false
}

// buildICMPv4Reply builds an ICMP echo reply (type 0) for req, echoing the
// identifier, sequence and payload of the request with addresses reversed.
func buildICMPv4Reply(req pktkit.Packet) []byte {
	icmp := req[req.IPv4HeaderLen():]
	if len(icmp) < 8 || icmp[0] != 8 {
		return nil
	}
	reply := make([]byte, len(icmp))
	copy(reply, icmp)
	reply[0] = 0 // echo reply
	reply[1] = 0 // code
	binary.BigEndian.PutUint16(reply[2:4], 0)
	binary.BigEndian.PutUint16(reply[2:4], pktkit.Checksum(reply))
	return wrapIPv4(req.IPv4DstAddr(), req.IPv4SrcAddr(), uint8(pktkit.ProtocolICMP), reply)
}

// buildICMPv6Reply builds an ICMPv6 echo reply (type 129) for req with the
// checksum computed over the IPv6 pseudo-header.
func buildICMPv6Reply(req pktkit.Packet) []byte {
	icmp := req.IPv6Payload()
	if len(icmp) < 8 || icmp[0] != 128 {
		return nil
	}
	reply := make([]byte, len(icmp))
	copy(reply, icmp)
	reply[0] = 129 // echo reply
	reply[1] = 0   // code
	binary.BigEndian.PutUint16(reply[2:4], 0)
	cs := slirp.IPv6Checksum(req.IPv6DstAddr().As16(), req.IPv6SrcAddr().As16(),
		uint8(pktkit.ProtocolICMPv6), uint32(len(reply)), reply)
	binary.BigEndian.PutUint16(reply[2:4], cs)
	return wrapIPv6(req.IPv6DstAddr(), req.IPv6SrcAddr(), uint8(pktkit.ProtocolICMPv6), reply)
}
