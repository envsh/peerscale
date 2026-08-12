// Package softun implements a user-space "tun" device built on pktkit/vclient.
//
// It is a fallback for nodes that cannot create a kernel tun device (no
// root/cap_net_admin): instead of transparently capturing local traffic, the
// application reaches the virtual LAN explicitly through the returned vc
// (Dial/Listen/HTTPClient). softun owns the local stack and all routing
// decisions (hairpin, ICMP/UDP/TCP replies, peer resolution); packets are
// forwarded to remote peers through the iptunnel transport, which registers
// the iptunnel/1.0 protocol and only shuttles whole IP packets.
package softun

import (
	"hash/crc64"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/KarpelesLab/pktkit"
	"github.com/KarpelesLab/pktkit/vclient"
	"github.com/envsh/libp2px/iptunnel"
	"github.com/envsh/libp2px/p2put"
)

const (
	vlanpfx = "10.0.0."
	ipv6pfx = "fd00::"
)

var (
	tunOnce sync.Once
	softTun *vclient.Client

	localMu     sync.Mutex
	localPeerID string
	addrDone    bool

	peerIPs   = make(map[string]string)
	peerIPsMu sync.Mutex
)

func ensureInit() {
	tunOnce.Do(func() {
		c := vclient.New()
		c.SetHandler(routeWrite)
		softTun = c
		startReaper()
	})
}

func ensureSelf(pid string) {
	localMu.Lock()
	if localPeerID == "" && pid != "" {
		localPeerID = pid
	}
	if addrDone || localPeerID == "" || softTun == nil {
		localMu.Unlock()
		return
	}
	ip := vlanpfx + strconv.Itoa(StringToHostPart(localPeerID))
	v6 := localIPv6Of(localPeerID)
	localMu.Unlock()

	if err := softTun.SetAddr(netip.MustParsePrefix(ip + "/24")); err != nil {
		log.Println("[softun] SetAddr:", err)
	}
	if v6 != "" {
		softTun.SetIPv6(net.ParseIP(v6))
	}
	localMu.Lock()
	addrDone = true
	localMu.Unlock()
}

// InitSoftTun initializes the user-space tun device. localPeerID is the local
// node's peer ID used to derive the virtual IP; an empty value defers address
// assignment until the local peer ID becomes known. It also registers this
// device as the inbound Sink of the iptunnel transport.
func InitSoftTun(localPeerID string) error {
	ensureInit()
	ensureSelf(localPeerID)
	iptunnel.SetSink(softunSink{})
	return nil
}

// softunSink is the inbound consumer registered with iptunnel: packets coming
// from peer streams are claimed by the local stack's services (ICMP/UDP/TCP)
// or injected into the vc device.
type softunSink struct{}

func (softunSink) Inbound(pkt pktkit.Packet) {
	localMu.Lock()
	id := localPeerID
	localMu.Unlock()
	ensureSelf(id)
	if !handleInbound(pkt) {
		if err := softTun.Send(pkt); err != nil {
			log.Printf("[softun] inject inbound %s -> %s: %v", pkt.SrcAddr(), pkt.DstAddr(), err)
		}
	}
}

// Device returns the user-space network stack. Applications use it to reach
// the virtual LAN (Dial/Listen/HTTPClient/Resolver). Returns nil before
// InitSoftTun.
func Device() *vclient.Client {
	return softTun
}

// WritePacket routes one locally-produced IP packet to its destination peer.
func WritePacket(pkt pktkit.Packet) error {
	return routeWrite(pkt)
}

// LocalIP returns this node's virtual IPv4 address (10.0.0.x).
func LocalIP() string {
	localMu.Lock()
	id := localPeerID
	localMu.Unlock()
	return vlanpfx + strconv.Itoa(StringToHostPart(id))
}

// StringToHostPart derives the 10.0.0.x host part from a peer ID (crc64),
// matching the algorithm used by fbvirtun.
func StringToHostPart(s string) int {
	tbl := crc64.MakeTable(crc64.ECMA)
	h := crc64.Checksum([]byte(s), tbl)
	return int(h%253) + 2
}

// LocalIPv6 returns this node's virtual IPv6 address (fd00::<host>), derived
// from the same crc64 host part as LocalIP. Returns "" before the local peer
// ID is known.
func LocalIPv6() string {
	localMu.Lock()
	id := localPeerID
	localMu.Unlock()
	return localIPv6Of(id)
}

func localIPv6Of(id string) string {
	if id == "" {
		return ""
	}
	return ipv6pfx + strconv.FormatInt(int64(StringToHostPart(id)), 16)
}

func routeWrite(pkt pktkit.Packet) error {
	if !pkt.IsValid() {
		return nil
	}
	if pkt.IsBroadcast() || pkt.IsMulticast() {
		log.Printf("[softun] drop broadcast/multicast %s -> %s", pkt.SrcAddr(), pkt.DstAddr())
		return nil
	}
	clearSynPendingForPacket(pkt)
	dst := pkt.DstAddr()
	if isLocalAddr(dst) {
		return hairpin(pkt)
	}
	if dst.Is4() {
		if !vlanContains4(dst) {
			log.Printf("[softun] drop external dst %s", dst)
			return nil
		}
		return routeToPeer(pkt, dst)
	}
	if !dst.Is6() || dst.Is4In6() || !vlanContains6(dst) {
		log.Printf("[softun] drop external dst %s", dst)
		return nil
	}
	return routeToPeer(pkt, dst)
}

func routeToPeer(pkt pktkit.Packet, dst netip.Addr) error {
	pid := peerIDByVirtAddr(dst)
	if pid == "" {
		log.Printf("[softun] drop unroutable dst %s", dst)
		return nil
	}
	if err := iptunnel.WriteToPeer(pid, pkt); err != nil {
		log.Printf("[softun] write to peer %s: %v", pid, err)
		return err
	}
	return nil
}

// isLocalAddr reports whether addr is one of this node's virtual addresses.
func isLocalAddr(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	if a == netip.MustParseAddr(LocalIP()) {
		return true
	}
	if v6 := LocalIPv6(); v6 != "" {
		if p6, err := netip.ParseAddr(v6); err == nil && a == p6 {
			return true
		}
	}
	return false
}

func vlanContains4(a netip.Addr) bool {
	if !a.Is4() {
		return false
	}
	b := a.As4()
	return b[0] == 10 && b[1] == 0 && b[2] == 0
}

func vlanContains6(a netip.Addr) bool {
	if !a.Is6() || a.Is4In6() {
		return false
	}
	b := a.As16()
	return b[0] == 0xfd && b[1] == 0 && b[2] == 0 && b[3] == 0 && b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0
}

func peerIDByVirtAddr(addr netip.Addr) string {
	key := addr.String()
	peerIPsMu.Lock()
	defer peerIPsMu.Unlock()
	if id, ok := peerIPs[key]; ok {
		return id
	}
	for _, id := range p2put.GetClusterPeers() {
		h := StringToHostPart(id)
		peerIPs[vlanpfx+strconv.Itoa(h)] = id
		peerIPs[ipv6pfx+strconv.FormatInt(int64(h), 16)] = id
	}
	return peerIPs[key]
}

// startReaper periodically clears stale TCP SYN-pending markers (the only
// local-stack state that can leak). Hub/hub-carrier reaping lives in iptunnel.
func startReaper() {
	go func() {
		t := time.NewTicker(30 * time.Second)
		for now := range t.C {
			if n := reapSynPending(now); n > 0 {
				log.Printf("[softun] reaped %d stale syn-pending entries", n)
			}
		}
	}()
}
