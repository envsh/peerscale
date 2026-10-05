#!/bin/sh
#
# pfroute-android.sh — Android tun sysctl + policy routing setup and verification
#
# Usage:
#   pfroute-android.sh sysctl  <ifname>
#   pfroute-android.sh setup   <ifname> <vlanpfx> <verify_ip> <is6>
#   pfroute-android.sh cleanup <vlanpfx>
#
# 参数约定与 pfroute-darwin.sh 的 setup 一致：<ifname> <vlanpfx> <verify_ip> <is6>。
# <vlanpfx> 是带尾点的形式（如 10.0.0.），子网写作 ${vlanpfx}0/24。
#
# sysctl  — 只写 tun 接口级，不写 all。
#           rp_filter 的生效值是 max(conf, all)，所以先读 all/rp_filter：
#           非 0 时接口级写 0 无效，直接报错退出，而不是静默写一个不生效的值。
#           accept_local 是 ORCONF(dev||all)，接口级自足，不需要动 all。
#           直接写 /proc/sys，不依赖 sysctl 二进制（Termux 一般没装，
#           Android 自带的在 /system/bin 且通常不在 PATH 里）。
# setup   — 补两条 pref 1 规则，让发往 mesh 子网的包先查 main 表。
#           from 与 to 都要：前者覆盖已绑定源地址的连接，后者覆盖未绑定源的 socket。
#           必须在 ip addr add 之后执行 —— lookup main 靠 addr add 装上的
#           connected 路由才命中，否则规则形同虚设。
#           最后回读验证两条规则都在 pref 1。
# cleanup — 删掉这两条规则。
#
# 解释器用 sh 而非 bash：Android 上没有 /bin/bash（Termux 的 bash 在
# $PREFIX/bin/bash，shebang 路径对不上）。脚本只用 POSIX 语法。
# ip 通过 PATH 查找，不写死路径。
#
# Exit codes:
#   0 success
#   1 usage error
#   2 sysctl write failed
#   3 ip rule add failed
#   4 verify failed

conf=/proc/sys/net/ipv4/conf

say() { echo "pfroute-android: $*"; }
err() { echo "pfroute-android: $*" >&2; }

# runip <args...> — 通过 PATH 查 ip，不写死路径
runip() {
	if ! command -v ip >/dev/null 2>&1; then
		err "no ip in PATH (Termux: pkg install iproute2)"
		return 127
	fi
	ip "$@"
}

# write_conf <name> <value> — 写 /proc/sys/net/ipv4/conf/<name>，同值跳过
write_conf() {
	_name=$1
	_val=$2
	_path=$conf/$_name
	if [ ! -e "$_path" ]; then
		err "sysctl FAIL $_path 不存在（tun 接口未注册？）"
		return 1
	fi
	_cur=$(cat "$_path" 2>/dev/null)
	if [ "$_cur" = "$_val" ]; then
		say "sysctl net.ipv4.conf.$_name=$_cur 已是目标值，跳过"
		return 0
	fi
	if ! echo "$_val" > "$_path" 2>/dev/null; then
		err "sysctl FAIL net.ipv4.conf.$_name $_cur -> $_val 写入失败，需 root"
		return 1
	fi
	say "sysctl net.ipv4.conf.$_name $_cur -> $(cat "$_path" 2>/dev/null)"
	return 0
}

mode=$1

case "$mode" in
sysctl)
	ifname=$2
	if [ -z "$ifname" ]; then
		err "Usage: $0 sysctl <ifname>"
		exit 1
	fi
	rc=0
	all_rp=$(cat "$conf/all/rp_filter" 2>/dev/null)
	say "基线 all/rp_filter=$all_rp all/accept_local=$(cat "$conf/all/accept_local" 2>/dev/null)"
	if [ "$all_rp" != "0" ]; then
		err "sysctl FAIL $ifname/rp_filter 不写：内核取 max(conf, all)=$all_rp，接口级写 0 无效"
		err "  需 root 手动 sysctl -w net.ipv4.conf.all.rp_filter=0"
		rc=2
	fi
	write_conf "$ifname/rp_filter" 0 || rc=2
	write_conf "$ifname/accept_local" 1 || rc=2
	exit $rc
	;;
setup)
	ifname=$2
	vlanpfx=$3
	verify_ip=$4
	is6=$5
	if [ -z "$ifname" ] || [ -z "$vlanpfx" ] || [ -z "$verify_ip" ]; then
		err "Usage: $0 setup <ifname> <vlanpfx> <verify_ip> <is6>"
		exit 1
	fi
	if [ "$is6" = "6" ]; then
		err "ip6 规则未实现，只支持 is6=4"
		exit 1
	fi
	subnet="${vlanpfx}0/24"
	rc=0
	for sel in from to; do
		if runip rule add pref 1 "$sel" "$subnet" lookup main; then
			say "rule 已添加 ip rule add pref 1 $sel $subnet lookup main"
		else
			if runip rule show 2>/dev/null | grep -q "^1:.*$sel .*$subnet.*main"; then
				say "rule pref 1 $sel $subnet lookup main 已存在"
			else
				err "rule FAIL ip rule add pref 1 $sel $subnet lookup main 需 root"
				err "  否则到 mesh 对端不通：能建 tun、能拿 IP，但 ping 和端口都不通"
				rc=3
			fi
		fi
	done
	got=$(runip rule show 2>/dev/null)
	for sel in from to; do
		if printf '%s\n' "$got" | grep -q "^1:.*$sel .*$subnet.*main"; then
			say "rule verify OK pref 1 $sel $subnet lookup main"
		else
			err "rule verify FAIL 缺 pref 1 $sel $subnet lookup main"
			err "  Android netd 的无条件规则在 pref 18000/19000/20000，不加则包走 wlan0 进不了 tun"
			rc=4
		fi
	done
	exit $rc
	;;
cleanup)
	vlanpfx=$2
	if [ -z "$vlanpfx" ]; then
		err "Usage: $0 cleanup <vlanpfx>"
		exit 1
	fi
	subnet="${vlanpfx}0/24"
	for sel in from to; do
		if runip rule del pref 1 "$sel" "$subnet" lookup main >/dev/null 2>&1; then
			say "rule 已删除 pref 1 $sel $subnet lookup main"
		fi
	done
	say "cleanup done"
	exit 0
	;;
*)
	err "Usage: $0 sysctl <ifname> | setup <ifname> <vlanpfx> <verify_ip> <is6> | cleanup <vlanpfx>"
	exit 1
	;;
esac



# 更新2610

#sysctl -w net.ipv4.conf.all.rp_filter=0
#sysctl -w net.ipv4.conf.utun3.rp_filter=0
#sysctl -w net.ipv4.conf.all.accept_local=1
#sysctl -w net.ipv4.conf.utun3.accept_local=1

#ip rule add pref 1 from 10.0.0.0/24 lookup main
#ip rule add pref 1 to 10.0.0.0/24 lookup main



# 验证
cat /proc/sys/net/ipv4/conf/all/rp_filter  # 应为 0
#cat /proc/sys/net/ipv4/conf/utun3/rp_filter  # 应为 0
cat  /proc/sys/net/ipv4/conf/all/accept_local # 应为 1
#cat  /proc/sys/net/ipv4/conf/utun3/accept_local # 应为 1


# 设置
# Android netd 在优先级 10000+ 插入的规则可能绕过 TUN 路由。经典确认案例：linuxdeploy + OpenVPN 用户报告 "tun0 RX=0"，最终解决方案是：

# ip rule add from all lookup main pref 1
