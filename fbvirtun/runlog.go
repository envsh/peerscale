package fbvirtun

import (
	"log"
	"os"
	"strings"
	"time"
)

func writeTunBuf(tag string, bufs [][]byte) {
	if Tunov == nil {
		log.Printf("tun: %s write FAIL: Tunov is nil", tag)
		return
	}
	if _, err := Tunov.Write(bufs[:1], tunOffset); err != nil {
		log.Printf("tun: %s write FAIL: %v (offset=%d bufsize=%d)", tag, err, tunOffset, tunBufSize)
	}
}

func readProc(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "err(" + err.Error() + ")"
	}
	return strings.TrimSpace(string(b))
}

// dottedKey 把 /proc/sys/net/ipv4/conf/utun3/rp_filter 转成
// net.ipv4.conf.utun3.rp_filter，供 sysctl -w 提示用。
func dottedKey(p string) string {
	return strings.ReplaceAll(strings.TrimPrefix(p, "/proc/sys/"), "/", ".")
}

func curTunName() string {
	if Tunov == nil {
		return ""
	}
	n, err := Tunov.Name()
	if err != nil {
		return ""
	}
	return n
}

var tunReadErrLast time.Time

func logTunReadErr(err error) {
	now := time.Now()
	if !tunReadErrLast.IsZero() && now.Sub(tunReadErrLast) < 30*time.Second {
		return
	}
	tunReadErrLast = now
	log.Printf("tun: Read FAIL: %v (offset=%d bufsize=%d) — 同类错误每 30s 最多一条", err, tunOffset, tunBufSize)
}
