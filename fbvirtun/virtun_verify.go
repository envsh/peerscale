package fbvirtun

import (
	"fmt"
	"log"
	"net"
	"strings"
)

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

// verifyTunSetup 所有平台默认执行,无开关/环境变量。跨平台核心(V1-V3)用标准库
// net,平台专属深检交给各 tag 文件实现的 verifyPlatformExtra。
func verifyTunSetup(ifname, selfIP string) {
	var st verifyState
	verifyLinkAndAddr(ifname, selfIP, &st)
	verifyPlatformExtra(ifname, selfIP, &st)
	if st.fail > 0 {
		log.Printf("virtun: verify: %d/%d PASS FAIL=[%s]",
			st.pass, st.pass+st.fail, strings.Join(st.names, ","))
	}
}

// verifyLinkAndAddr 用标准库 net(InterfaceByName/Flags/Addrs)替代
// netlink.LinkByName/AddrList:LINUX/MACOS/WINDOWS 同一实现,语义等价。
func verifyLinkAndAddr(ifname, selfIP string, st *verifyState) {
	if ifname == "" {
		st.bad("V1 tun-name", "取不到 tun 名(Tunov 为 nil 或 Name() 失败)")
		return
	}
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		st.bad("V1 "+ifname, err.Error())
		return
	}
	st.ok()
	if iface.Flags&net.FlagUp != 0 {
		st.ok()
	} else {
		st.bad("V2 up", fmt.Sprintf("dev=%s flags=%v", ifname, iface.Flags))
	}
	addrs, err := iface.Addrs()
	if err != nil {
		st.bad("V3 addr", err.Error())
		return
	}
	var list []string
	found := false
	want := net.ParseIP(selfIP)
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn == nil {
			continue
		}
		list = append(list, ipn.String())
		if selfIP != "" && want != nil && ipn.IP.Equal(want) {
			found = true
		}
	}
	if found || (selfIP == "" && len(list) > 0) {
		st.ok()
	} else {
		st.bad("V3 addr", fmt.Sprintf("want=%s have=%v", selfIP, list))
	}
}
