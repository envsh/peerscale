// Package iptunnel is the pure packet-forwarding layer for the virtual LAN.
// It registers the iptunnel/1.0 protocol and shuttles whole IP packets between
// per-peer libp2p streams and a single local Sink (the tun device). It makes
// no routing or local-stack decisions: outbound packets arrive via
// WriteToPeer, inbound packets are handed to the Sink registered with SetSink.
package iptunnel

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KarpelesLab/pktkit"
	"github.com/envsh/libp2px/p2put"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-msgio"
)

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
			return
		}
		if s := sink.Load(); s != nil {
			(*s).Inbound(pktkit.Packet(pkt))
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
