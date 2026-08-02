// Package softun implements a user-space "tun" device built on pktkit/vclient.
//
// It is a fallback for nodes that cannot create a kernel tun device (no
// root/cap_net_admin): instead of transparently capturing local traffic, the
// application reaches the virtual LAN explicitly through the returned vc
// (Dial/Listen/HTTPClient). The wire is identical to iptunnel — whole IP
// packets framed with msgio over per-peer streams — so a softun node can
// interoperate with any node serving the same protocol.
package softun

import (
	"context"
	"hash/crc64"
	"log"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KarpelesLab/pktkit"
	"github.com/KarpelesLab/pktkit/vclient"
	"github.com/envsh/libp2px/p2put"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-msgio"
)

const (
	tunnelProto = "iptunnel/1.0"
	vlanpfx     = "10.0.0."
	ipv6pfx     = "fd00::"
	udpBufSize  = 65535
	carrierIdle = 5 * time.Minute
	hubIdle     = 2 * time.Minute
)

var (
	tunOnce sync.Once
	softTun *vclient.Client

	localMu     sync.Mutex
	localPeerID string
	addrDone    bool

	hubsMu sync.Mutex
	hubs   = make(map[string]*tunnelHub)

	peerIPs   = make(map[string]string)
	peerIPsMu sync.Mutex
)

type tunnelCarrier struct {
	s    network.Stream
	w    msgio.WriteCloser
	dead atomic.Bool
}

type tunnelHub struct {
	peerID   string
	mu       sync.Mutex
	carriers []*tunnelCarrier
	opening  bool
	lastUse  time.Time
}

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
// assignment until the first stream is seen.
func InitSoftTun(localPeerID string) error {
	ensureInit()
	ensureSelf(localPeerID)
	return nil
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
// matching the algorithm used by iptunnel and fbvirtun.
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

// HandleInboundStream attaches an inbound p2p stream to the tunnel device.
// This is the entry point that the iptunnel protocol handler should call.
func HandleInboundStream(s network.Stream) {
	ensureInit()
	ensureSelf(s.Conn().LocalPeer().String())
	hubFor(s.Conn().RemotePeer().String()).attach(s)
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
	hubFor(pid).write(pkt)
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

func hubFor(peerID string) *tunnelHub {
	hubsMu.Lock()
	defer hubsMu.Unlock()
	h := hubs[peerID]
	if h == nil {
		h = &tunnelHub{peerID: peerID}
		hubs[peerID] = h
	}
	return h
}

func (h *tunnelHub) attach(s network.Stream) {
	c := &tunnelCarrier{s: s, w: msgio.NewWriter(s)}
	h.mu.Lock()
	h.carriers = append(h.carriers, c)
	h.lastUse = time.Now()
	h.mu.Unlock()
	go h.pump(c)
}

func (h *tunnelHub) detach(c *tunnelCarrier) {
	c.dead.Store(true)
	h.mu.Lock()
	for i, x := range h.carriers {
		if x == c {
			h.carriers = append(h.carriers[:i], h.carriers[i+1:]...)
			break
		}
	}
	h.mu.Unlock()
	c.s.Close()
}

func (h *tunnelHub) pump(c *tunnelCarrier) {
	defer h.detach(c)
	r := msgio.NewReaderSize(c.s, udpBufSize)
	for {
		c.s.SetReadDeadline(time.Now().Add(carrierIdle))
		pkt, err := r.ReadMsg()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		if softTun == nil {
			r.ReleaseMsg(pkt)
			return
		}
		ensureSelf(c.s.Conn().LocalPeer().String())
		p := pktkit.Packet(pkt)
		if !handleInbound(p) {
			softTun.Send(p)
		}
		r.ReleaseMsg(pkt)
	}
}

func (h *tunnelHub) write(pkt pktkit.Packet) {
	h.mu.Lock()
	h.lastUse = time.Now()
	for _, c := range h.carriers {
		if c.dead.Load() {
			continue
		}
		if err := c.w.WriteMsg([]byte(pkt)); err != nil {
			c.dead.Store(true)
			go c.s.Close()
			continue
		}
		h.mu.Unlock()
		return
	}
	h.maybeOpenLocked()
	h.mu.Unlock()
}

func (h *tunnelHub) maybeOpenLocked() {
	if h.opening {
		return
	}
	h.opening = true
	go h.openAsync()
}

func (h *tunnelHub) openAsync() {
	defer func() {
		h.mu.Lock()
		h.opening = false
		h.mu.Unlock()
	}()
	s, err := p2put.OpenStream(context.Background(), h.peerID, tunnelProto)
	if err != nil {
		return
	}
	h.attach(s)
}

func startReaper() {
	go func() {
		t := time.NewTicker(30 * time.Second)
		for now := range t.C {
			reapSynPending(now)
			hubsMu.Lock()
			for id, h := range hubs {
				h.mu.Lock()
				live := false
				for _, c := range h.carriers {
					if !c.dead.Load() {
						live = true
						break
					}
				}
				idle := now.Sub(h.lastUse) > hubIdle
				busy := h.opening || live
				h.mu.Unlock()
				if !busy && idle {
					delete(hubs, id)
				}
			}
			hubsMu.Unlock()
		}
	}()
}
