package iptunnel

import (
	"time"
)

// startReaper periodically evicts idle hubs so the hubs map does not grow
// without bound. A hub is evicted once it has no live carrier and has been
// unused for hubIdle.
func startReaper() {
	go func() {
		t := time.NewTicker(30 * time.Second)
		for now := range t.C {
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
