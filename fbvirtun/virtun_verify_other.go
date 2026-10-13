//go:build !linux && !android && !darwin

package fbvirtun

import (
	"log"
	"runtime"
)

// verifyPlatformExtra 在 windows/freebsd 等平台仅记 INFO:V1-V3 已由标准库 net
// 完成;路由/防火墙深检在对应平台尚未实现,不报 FAIL。
func verifyPlatformExtra(ifname, selfIP string, st *verifyState) {
	log.Printf("virtun: verify INFO: %s 平台路由/防火墙深检未实现 (ifname=%s ip=%s)",
		runtime.GOOS, ifname, selfIP)
}
