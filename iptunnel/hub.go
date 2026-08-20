// Package iptunnel is the pure packet-forwarding layer for the virtual LAN.
// It registers the iptunnel/1.0 protocol and shuttles whole IP packets between
// per-peer libp2p streams and a single local Sink (the tun device). It makes
// no routing or local-stack decisions: outbound packets arrive via
// WriteToPeer, inbound packets are handed to the Sink registered with SetSink.
package iptunnel

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KarpelesLab/pktkit"
	"github.com/envsh/libp2px/p2put"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-msgio"
)

// ErrNoCarrier is returned by write when no live carrier is available to
// deliver the packet. Callers (vtcp) should treat this as a transport
// failure and reset their retransmission timer for faster recovery.
var ErrNoCarrier = errors.New("iptunnel: no live carrier")

const (
	tunnelProto = "iptunnel/1.0"
	udpBufSize  = 65535
	carrierIdle = 5 * time.Minute
	hubIdle     = 2 * time.Minute
)

var (
	hubsMu sync.Mutex
	hubs   = make(map[string]*tunnelHub)
)

type tunnelCarrier struct {
	s         network.Stream
	w         msgio.WriteCloser
	dead      atomic.Bool
	direction network.Direction
	created   time.Time
}

type tunnelHub struct {
	peerID   string
	mu       sync.Mutex
	carriers []*tunnelCarrier
	opening  bool
	lastUse  time.Time
	reattached bool // set true when attach new carrier stream
}

// hubFor returns the hub that owns the streams to peerID, creating it on
// first use. A hub is idle-reaped by startReaper once it has no live carrier.
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

func (h *tunnelHub) logPeerID() string {
	id, err := peer.Decode(h.peerID)
	if err != nil {
		return h.peerID
	}
	return id.ShortString()
}

func (h *tunnelHub) attach(s network.Stream) {
	c := &tunnelCarrier{
		s:         s,
		w:         msgio.NewWriter(s),
		direction: s.Stat().Direction,
		created:   time.Now(),
	}
	h.mu.Lock()
	var live []*tunnelCarrier
	for _, old := range h.carriers {
		if old.direction == c.direction && !old.dead.Load() {
			log.Printf("[iptunnel] attach: remove old %s carrier to %s", c.direction, h.logPeerID())
			old.dead.Store(true)
			continue
		}
		live = append(live, old)
	}
	live = append(live, c)
	h.carriers = live
	h.lastUse = time.Now()
	h.reattached = true
	count := len(h.carriers)
	h.mu.Unlock()
	log.Printf("[iptunnel] attach: carrier to %s added (%s, total=%d)", h.logPeerID(), c.direction, count)
	go h.pump(c)
}

func (h *tunnelHub) detach(c *tunnelCarrier) {
	alive := time.Since(c.created)
	log.Printf("[iptunnel] carrier to %s detached (%s, alive=%v)", h.logPeerID(), c.direction, alive)
	c.dead.Store(true)
	h.mu.Lock()
	found := false
	for i, x := range h.carriers {
		if x == c {
			h.carriers = append(h.carriers[:i], h.carriers[i+1:]...)
			found = true
			break
		}
	}
	if found {
		h.maybeOpenLocked("detach: stream lost")
	}
	h.mu.Unlock()
	c.s.Close()
}

// pump reads whole IP packets off a carrier stream and forwards them to the
// registered Sink. Packets are dropped while no Sink is set (the tun device
// has not been wired up yet).
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
			h.mu.Lock()
			total := len(h.carriers)
			h.mu.Unlock()
			log.Printf("[iptunnel] pump: read error from %s (%s, total=%d): %v", h.logPeerID(), c.direction, total, err)
			return
		}
		if s := sink.Load(); s != nil {
			(*s).Inbound(pktkit.Packet(pkt))
		}
		r.ReleaseMsg(pkt)
	}
}

func (h *tunnelHub) write(pkt pktkit.Packet) error {
	h.mu.Lock()
	h.lastUse = time.Now()

	var live []*tunnelCarrier
	for _, c := range h.carriers {
		if c.dead.Load() {
			continue
		}
		live = append(live, c)
	}

	if len(live) == 0 {
		log.Printf("[iptunnel] write to %s: no live carrier, opening new stream", h.logPeerID())
		h.maybeOpenLocked("write: no live carrier")
	}
	h.mu.Unlock()

	var lastErr error
	for _, c := range live {
		// log.Printf("[iptunnel] write to %s: trying %s len=%d", h.logPeerID(), c.direction, len(pkt))
		err := c.w.WriteMsg([]byte(pkt))
		if err == nil && h.reattached {
			log.Printf("[iptunnel] write to %s succ (%s): %v", h.logPeerID(), c.direction, err)
			h.reattached = false
		}
		if err != nil {
			log.Printf("[iptunnel] write to %s failed (%s): %v", h.logPeerID(), c.direction, err)
			lastErr = err
			c.dead.Store(true)
			go c.s.Close()
			continue
		}
		return nil
	}
	log.Printf("[iptunnel] write to %s: packet dropped len=%d (%d live carriers all failed)", h.logPeerID(), len(pkt), len(live))
	h.mu.Lock()
	h.maybeOpenLocked("write: all carriers failed")
	h.mu.Unlock()
	if lastErr != nil {
		return lastErr
	}
	return ErrNoCarrier
}

func (h *tunnelHub) maybeOpenLocked(reason string) {
	if h.opening {
		return
	}
	log.Printf("[iptunnel] %s: opening stream to %s", reason, h.logPeerID())
	h.opening = true
	go h.openPeerStreamAsync()
}

func (h *tunnelHub) openPeerStreamAsync() {
	defer func() {
		h.mu.Lock()
		h.opening = false
		h.mu.Unlock()
	}()
	s, err := p2put.OpenStream(context.Background(), h.peerID, tunnelProto)
	if err != nil {
		log.Printf("[iptunnel] open stream to %s failed: %v", h.logPeerID(), err)
		return
	}
	log.Printf("[iptunnel] stream to %s opened", h.logPeerID())
	h.attach(s)
}
