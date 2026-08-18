// Package iptunnel is the pure packet-forwarding layer for the virtual LAN
// (see hub.go). This file defines the tiny transport interface exposed to the
// tun device (softun, fbvirtun, ...): register a Sink for inbound packets and
// call WriteToPeer for outbound packets. All routing decisions live in the tun
// device, never here.
package iptunnel

import (
	"log"
	"sync/atomic"

	"github.com/KarpelesLab/pktkit"
	"github.com/envsh/libp2px/p2put"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// ShouldReject, when set, is consulted on every inbound stream before it is
// attached; a rejected stream is reset.
var ShouldReject func(network.Stream) bool

// Sink consumes whole IP packets received from remote peers. The tun device
// implements this and registers itself with SetSink.
type Sink interface {
	Inbound(pkt pktkit.Packet)
}

var sink atomic.Pointer[Sink]

// SetSink registers the local receiver for packets arriving from peer
// streams. Packets are dropped until a Sink is registered.
func SetSink(s Sink) {
	sink.Store(&s)
}

// WriteToPeer forwards one whole IP packet to the remote peer. It is the only
// outbound transport a tun device needs; peer resolution and all routing
// decisions stay in the tun device.
func WriteToPeer(peerID string, pkt pktkit.Packet) error {
	return hubFor(peerID).write(pkt)
}

func init() {
	startReaper()
	p2put.MustRegisterProtocol(tunnelProto, handleStream, true)
}

// handleStream is the protocol entry point: after the optional reject check,
// the inbound stream is attached to the remote peer's hub, from which packets
// flow to the registered Sink.
func handleStream(s network.Stream) {
	if ShouldReject != nil && ShouldReject(s) {
		s.Reset()
		return
	}
	peerID := s.Conn().RemotePeer().String()
	log.Printf("[iptunnel] handleStream: incoming stream from %s", shortPeerID(peerID))
	hubFor(peerID).attach(s)
}

func shortPeerID(raw string) string {
	id, err := peer.Decode(raw)
	if err != nil {
		return raw
	}
	return id.ShortString()
}
