//go:build darwin

package fbvirtun

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
)

// verifyPlatformExtra 在 darwin 用 macOS 原生工具做真实校验(netlink 不存在):
//
//	V4/V9: route -n get —— 与 pfroute-darwin.sh 同一判据(interface|gateway 指向 ifname)
//	V7   : sysctl net.inet.ip.forwarding(观察项,不断言;setupDarwinRoutes 已写 1)
//	V8   : pfctl -sr 中引用本接口的规则(观察项,需 root)
//	V5/V6/V10: ip rule 概念仅存在于 Android 网络栈,记 INFO 跳过
func verifyPlatformExtra(ifname, selfIP string, st *verifyState) {
	if ifname == "" {
		st.bad("V4 route", "取不到 tun 名(Tunov 为 nil 或 Name() 失败)")
		return
	}
	ip := net.ParseIP(selfIP)
	if ip == nil {
		ip = net.ParseIP(VlanPfx + "1")
	}
	if ip == nil {
		st.bad("V4 route", fmt.Sprintf("selfIP=%q 且 VlanPfx=%q 均无法解析出目标 IP", selfIP, VlanPfx))
		return
	}
	out, err := exec.Command("/sbin/route", "-n", "get", ip.String()).CombinedOutput()
	if err != nil {
		st.bad("V4 route", fmt.Sprintf("route -n get %s FAIL: %v: %s",
			ip, err, strings.TrimSpace(string(out))))
		return
	}
	text := string(out)
	hit := ""
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "interface:") || strings.HasPrefix(l, "gateway:") {
			if strings.HasSuffix(l, ifname) {
				hit = l
				break
			}
		}
	}
	if hit == "" {
		st.bad("V4 route", fmt.Sprintf("route -n get %s 未指向 %s(期望 interface/gateway), 结果:\n%s", ip, ifname, text))
		return
	}
	st.ok()
	log.Printf("virtun: verify INFO V4: route -n get %s -> %s", ip, hit)

	log.Printf("virtun: verify INFO V9: route -n get %s 全量:\n%s", ip, text)

	fwd, err := exec.Command("/usr/sbin/sysctl", "-n", "net.inet.ip.forwarding").CombinedOutput()
	if err != nil {
		log.Printf("virtun: verify INFO V7: sysctl net.inet.ip.forwarding FAIL: %v (观察项,不断言)", err)
	} else {
		log.Printf("virtun: verify INFO V7: net.inet.ip.forwarding=%s (setupDarwinRoutes 写 1)", strings.TrimSpace(string(fwd)))
	}

	pf, err := exec.Command("/sbin/pfctl", "-sr").CombinedOutput()
	if err != nil {
		log.Printf("virtun: verify INFO V8: pfctl -sr FAIL: %v (需 root,观察项,不断言)", err)
	} else {
		var hits []string
		for _, l := range strings.Split(string(pf), "\n") {
			l = strings.TrimSpace(l)
			if l != "" && strings.Contains(l, ifname) {
				hits = append(hits, l)
			}
		}
		log.Printf("virtun: verify INFO V8: pfctl -sr 中涉及 %s 的规则=%v", ifname, hits)
	}

	log.Printf("virtun: verify INFO V5/V6/V10: ip rule(uidrange/fwmark/pref1) 仅适用于 Android 网络栈,已跳过")
}
