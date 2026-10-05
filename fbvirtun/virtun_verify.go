package fbvirtun

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/vishvananda/netlink"
)

const verifyMainTable = 254

type verifyState struct {
	pass, fail int
	names      []string
}

func (s *verifyState) ok() { s.pass++ }

func (s *verifyState) bad(name, detail string) {
	s.fail++
	s.names = append(s.names, name)
	log.Printf("virtun: verify FAIL %s: %s", name, detail)
}

func verifyEnabled() bool { return os.Getenv("FBVIRTUN_VERIFY") != "0" }

func verifyTunSetup(ifname, selfIP string) {
	if !verifyEnabled() {
		return
	}
	var st verifyState
	switch runtime.GOOS {
	case "linux", "android":
		verifyLinkAndAddr(ifname, selfIP, &st)
		if runtime.GOOS == "android" {
			verifyAndroidSnapshot(ifname, &st)
		}
	}
	if st.fail > 0 {
		log.Printf("virtun: verify: %d/%d PASS FAIL=[%s]",
			st.pass, st.pass+st.fail, strings.Join(st.names, ","))
	}
}

func verifyLinkAndAddr(ifname, selfIP string, st *verifyState) {
	if ifname == "" {
		st.bad("V1 tun-name", "取不到 tun 名(Tunov 为 nil 或 Name() 失败)")
		return
	}
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		st.bad("V1 "+ifname, err.Error())
		return
	}
	st.ok()
	if link.Attrs().Flags&net.FlagUp != 0 {
		st.ok()
	} else {
		st.bad("V2 up", fmt.Sprintf("dev=%s flags=%v", ifname, link.Attrs().Flags))
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		st.bad("V3 addr", err.Error())
		return
	}
	var list []string
	found := false
	for _, a := range addrs {
		list = append(list, a.IPNet.String())
		if selfIP != "" && a.IP.Equal(net.ParseIP(selfIP)) {
			found = true
		}
	}
	if found || (selfIP == "" && len(list) > 0) {
		st.ok()
	} else {
		st.bad("V3 addr", fmt.Sprintf("want=%s have=%v", selfIP, list))
	}
	verifyMainTableRoute(link, st)
}

func verifyMainTableRoute(link netlink.Link, st *verifyState) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		st.bad("V4 route", err.Error())
		return
	}
	var hits []string
	for _, r := range routes {
		if r.Table != verifyMainTable || r.Dst == nil {
			continue
		}
		if r.LinkIndex == link.Attrs().Index {
			hits = append(hits, fmt.Sprintf("%s oif-index=%d", r.String(), r.LinkIndex))
		}
	}
	if len(hits) > 0 {
		st.ok()
		log.Printf("virtun: verify INFO V4: main(%d) 表 tun 路由 %v", verifyMainTable, hits)
		return
	}
	st.bad("V4 route", fmt.Sprintf("main(%d) 表内无 oif-index=%d(%s) 的非默认路由",
		verifyMainTable, link.Attrs().Index, link.Attrs().Name))
}

func verifyAndroidSnapshot(ifname string, st *verifyState) {
	uid := os.Getuid()
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		st.bad("V5 rules", err.Error())
	} else {
		var sums, hits []string
		for _, r := range rules {
			sums = append(sums, ruleSummary(r))
			if r.UIDRange != nil && uint32(uid) >= r.UIDRange.Start && uint32(uid) <= r.UIDRange.End {
				hits = append(hits, fmt.Sprintf("pref %d -> table %d", r.Priority, r.Table))
			}
		}
		log.Printf("virtun: verify INFO V5: ip rule(%d 条)=[%s]", len(rules), strings.Join(sums, " | "))
		if len(hits) == 0 {
			log.Printf("virtun: verify INFO V5: uid %d 未命中任何 uidrange 规则", uid)
		} else {
			log.Printf("virtun: verify INFO V5: uid %d 命中 %v", uid, hits)
		}
		log.Printf("virtun: verify INFO V6: netd 插入的 uidrange/fwmark 规则=[%s]", netdRuleSummary(rules))
	}
	verifySysctls(ifname, st)
	verifyIptablesRO(ifname)
	verifyRouteGet()
}

func ruleSummary(r netlink.Rule) string {
	s := fmt.Sprintf("%d->%d", r.Priority, r.Table)
	if r.UIDRange != nil {
		s += fmt.Sprintf(" uidrange %d-%d", r.UIDRange.Start, r.UIDRange.End)
	}
	if r.Mark != 0 {
		mask := uint32(0)
		if r.Mask != nil {
			mask = *r.Mask
		}
		s += fmt.Sprintf(" fwmark %#x/%#x", r.Mark, mask)
	}
	if r.IifName != "" {
		s += " iif " + r.IifName
	}
	if r.OifName != "" {
		s += " oif " + r.OifName
	}
	if r.Dst != nil {
		s += " to " + r.Dst.String()
	}
	if r.Src != nil {
		s += " from " + r.Src.String()
	}
	if r.Type != 0 {
		s += fmt.Sprintf(" type=%d", r.Type)
	}
	return s
}

func netdRuleSummary(rules []netlink.Rule) string {
	var out []string
	for _, r := range rules {
		if r.Priority <= 1 {
			continue
		}
		if r.UIDRange != nil || r.Mark != 0 {
			out = append(out, ruleSummary(r))
		}
	}
	if len(out) == 0 {
		return "无 uidrange/fwmark 规则"
	}
	return strings.Join(out, " | ")
}

func verifySysctls(ifname string, st *verifyState) {
	dev := "/proc/sys/net/ipv4/conf/" + ifname
	log.Printf("virtun: verify INFO V7: default/rp_filter=%s default/accept_local=%s"+
		" (pfroute-android.sh 在 android 上从未执行,以下均为系统默认值)",
		readProc("/proc/sys/net/ipv4/conf/default/rp_filter"),
		readProc("/proc/sys/net/ipv4/conf/default/accept_local"))
	checks := []struct{ name, path, want, why string }{
		{"all/rp_filter", "/proc/sys/net/ipv4/conf/all/rp_filter", "0",
			"严格反向路径校验会丢掉从 tun 收到的包"},
		{ifname + "/rp_filter", dev + "/rp_filter", "0",
			"tun 接口需关闭 rp_filter"},
		{"all/accept_local", "/proc/sys/net/ipv4/conf/all/accept_local", "1",
			"=0 时内核丢弃 tun 上「源地址是本机地址」的包,表现为能建 tun、能拿 IP,但 peer ping 不通"},
		{ifname + "/accept_local", dev + "/accept_local", "1",
			"同上,tun 接口自身必须为 1"},
	}
	for _, c := range checks {
		got := readProc(c.path)
		if got == c.want {
			st.ok()
			continue
		}
		st.bad("V7 "+c.name, fmt.Sprintf("got=%q want=%q — %s\n"+
			"  修复(需 root,本程序只提示不执行): sysctl -w %s=%s",
			got, c.want, c.why, strings.TrimPrefix(c.path, "/proc/sys/"), c.want))
	}
}

func verifyIptablesRO(ifname string) {
	bin := ""
	for _, c := range []string{"iptables-nft", "iptables-legacy", "iptables"} {
		if out, err := exec.Command(c, "-V").CombinedOutput(); err == nil {
			bin = c
			log.Printf("virtun: verify INFO V8: iptables backend=%s (%s)", c, strings.TrimSpace(string(out)))
			break
		}
	}
	if bin == "" {
		log.Printf("virtun: verify INFO V8: 未找到 iptables 可执行文件")
		return
	}
	out, err := exec.Command(bin, "-S", "OUTPUT").CombinedOutput()
	if err != nil {
		log.Printf("virtun: verify INFO V8: %s -S OUTPUT FAIL: %v", bin, err)
		return
	}
	var hits []string
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && strings.Contains(l, ifname) {
			hits = append(hits, l)
		}
	}
	log.Printf("virtun: verify INFO V8: %s OUTPUT 中涉及 %s 的规则=%v", bin, ifname, hits)
}

func verifyRouteGet() {
	ip := net.ParseIP(VlanPfx + "1")
	if ip == nil {
		return
	}
	routes, err := netlink.RouteGet(ip)
	if err != nil {
		log.Printf("virtun: verify INFO V9: routeGet FAIL %v (uid %d 视角,不代表 app uid)", err, os.Getuid())
		return
	}
	if len(routes) == 0 {
		log.Printf("virtun: verify INFO V9: routeGet 无结果")
		return
	}
	log.Printf("virtun: verify INFO V9: routeGet %s -> %s (uid %d 视角,不代表 app uid)",
		ip, routes[0].String(), os.Getuid())
}