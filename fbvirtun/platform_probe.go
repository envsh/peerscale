package fbvirtun

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

// platInfo 是配置 tun 前置条件所需的系统事实，全部靠运行时探测得到，
// 不写死任何命令路径。
type platInfo struct {
	GOOS    string
	Android bool
	How     string // Android 判定依据
	Root    bool
	Release string
	SDK     string
	Kernel  string
}

// detectAndroid 不只看 runtime.GOOS：GOOS=linux 构建的二进制跑在 Termux 上时
// GOOS 就是 linux，但 netd 规则照样存在、策略规则照样要补，所以再叠一层探测。
// 命中即返回依据，用于日志事后复核。
func detectAndroid() (bool, string) {
	if runtime.GOOS == "android" {
		return true, "GOOS"
	}
	for _, k := range []string{"ANDROID_ROOT", "ANDROID_DATA", "PREFIX"} {
		if os.Getenv(k) != "" {
			return true, "env:" + k
		}
	}
	if _, err := os.Stat("/system/build.prop"); err == nil {
		return true, "/system/build.prop"
	}
	if _, err := os.Stat("/system/bin/toolbox"); err == nil {
		return true, "/system/bin/toolbox"
	}
	return false, ""
}

// parseAndroidVersion 只读版本号，用于日志诊断，不做任何阈值判断 ——
// 该不该配路由取决于实际行为，不取决于版本号。
func parseAndroidVersion() (release, sdk string) {
	b, err := os.ReadFile("/system/build.prop")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		switch {
		case strings.HasPrefix(line, "ro.build.version.release="):
			release = strings.TrimSpace(strings.TrimPrefix(line, "ro.build.version.release="))
		case strings.HasPrefix(line, "ro.build.version.sdk="):
			sdk = strings.TrimSpace(strings.TrimPrefix(line, "ro.build.version.sdk="))
		}
	}
	return
}

func detectPlat() platInfo {
	p := platInfo{GOOS: runtime.GOOS, Root: os.Geteuid() == 0}
	p.Android, p.How = detectAndroid()
	p.Release, p.SDK = parseAndroidVersion()
	p.Kernel = readProc("/proc/sys/kernel/osrelease")
	return p
}

func (p platInfo) String() string {
	return fmt.Sprintf("GOOS=%s android=%v(%s) root=%v release=%s sdk=%s kernel=%s",
		p.GOOS, p.Android, p.How, p.Root, p.Release, p.SDK, p.Kernel)
}
