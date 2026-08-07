package softun

import (
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// lo-port-map (loportmap) transparently serves this node's virtual addresses as
// the loopback interface: a TCP connection to virtualIP:port is proxied to the
// local 127.0.0.1:port service, so applications listening on lo (0.0.0.0) are
// reachable from the virtual LAN without any packet rewrite. Both ends are
// independent TCP connections, so no sequence tracking is needed.
//
// Listeners are registered lazily on first contact (after probing that the
// loopback service is actually listening, preserving connection-refused
// semantics) and reaped after lpmTTL of inactivity so they cannot accumulate.
type lpmEntry struct {
	ln          net.Listener
	lastTouched time.Time
}

var (
	// lpmTTL is the inactivity period after which an idle proxy listener is
	// closed and its virtual port released. Variable for tests.
	lpmTTL = 5 * time.Minute

	lpmProbeTimeout = 250 * time.Millisecond

	lpmMu        sync.Mutex
	lpmEnabled   bool
	lpmListeners = make(map[uint16]*lpmEntry)

	lpmGCOnce sync.Once
)

// EnableLoPortMap turns on lo port mapping: connections to this node's virtual
// addresses are proxied to the matching 127.0.0.1 port. Disabled by default.
func EnableLoPortMap() error {
	ensureInit()
	lpmMu.Lock()
	lpmEnabled = true
	lpmMu.Unlock()
	startLoPortMapGC()
	return nil
}

// DisableLoPortMap stops new port mapping: registered proxy listeners are
// closed and their virtual ports released. Connections already accepted keep
// running until they close.
func DisableLoPortMap() {
	lpmMu.Lock()
	lpmEnabled = false
	for _, e := range lpmListeners {
		e.ln.Close()
	}
	lpmListeners = make(map[uint16]*lpmEntry)
	lpmMu.Unlock()
}

// ensureLoPortMapPort makes sure a proxy listener exists for port (when
// enabled and a loopback service is present). It reports whether an inbound
// SYN for port should be handled by the port map. Called before the SYN is
// injected into the vc stack.
func ensureLoPortMapPort(port uint16) bool {
	lpmMu.Lock()
	defer lpmMu.Unlock()
	if !lpmEnabled {
		return false
	}
	if e, ok := lpmListeners[port]; ok {
		e.lastTouched = time.Now()
		return true
	}
	// Probe the loopback service first so closed ports keep their
	// connection-refused semantics instead of being accepted by a phantom
	// listener.
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(port)), lpmProbeTimeout)
	if err != nil {
		return false
	}
	c.Close()
	l, err := softTun.Listen("tcp", ":"+strconv.Itoa(int(port)))
	if err != nil {
		// Address already in use: the application owns the port.
		return false
	}
	e := &lpmEntry{ln: l, lastTouched: time.Now()}
	lpmListeners[port] = e
	go lpmAccept(e)
	return true
}

// lpmAccept hands accepted virtual connections to the loopback bridge.
func lpmAccept(e *lpmEntry) {
	for {
		conn, err := e.ln.Accept()
		if err != nil {
			return
		}
		go bridgeLoPort(conn)
	}
}

// bridgeLoPort proxies one accepted virtual connection to the loopback service
// on the same port. The two TCP connections are independent; bytes flow both
// ways until either side closes.
func bridgeLoPort(vcConn net.Conn) {
	addr, ok := vcConn.LocalAddr().(*net.TCPAddr)
	if !ok {
		vcConn.Close()
		return
	}
	phys, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(addr.Port))
	if err != nil {
		vcConn.Close()
		return
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(phys, vcConn)
		if t, ok := phys.(*net.TCPConn); ok {
			t.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		io.Copy(vcConn, phys)
		vcConn.Close()
	}()
	wg.Wait()
	phys.Close()
}

// startLoPortMapGC launches the single reaper that closes idle proxy
// listeners. Idempotent.
func startLoPortMapGC() {
	lpmGCOnce.Do(func() {
		go func() {
			t := time.NewTicker(30 * time.Second)
			for now := range t.C {
				reapLoPortMap(now)
			}
		}()
	})
}

// reapLoPortMap closes proxy listeners idle for longer than lpmTTL, releasing
// their virtual ports. Accepted connections are independent of the listener,
// so active bridges keep running; a connection accepted concurrently with the
// close is left to the vc stack to reap once its peer closes.
func reapLoPortMap(now time.Time) {
	lpmMu.Lock()
	for p, e := range lpmListeners {
		if now.Sub(e.lastTouched) <= lpmTTL {
			continue
		}
		e.ln.Close()
		delete(lpmListeners, p)
	}
	lpmMu.Unlock()
}
