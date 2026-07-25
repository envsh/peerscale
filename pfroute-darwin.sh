#!/bin/bash
#
# pfroute-darwin.sh — macOS utun routing setup and verification
#
# Usage:
#   pfroute-darwin.sh setup <ifname> <vlanpfx> <verify_ip> <is6>
#   pfroute-darwin.sh cleanup
#
# setup — Enables IP forwarding, adds v4 subnet route (idempotent),
#         conditionally adds the v6 host route, then verifies that
#         "route -n get <verify_ip>" shows interface/gateway <ifname>.
# cleanup — Deletes the v4 subnet route.
#
# Exit codes:
#   0 success
#   1 sysctl failed
#   2 v6 route add failed
#   3 route get failed
#   4 route get returned wrong interface

mode=$1
case "$mode" in
setup)
	ifname=$2
	pfx=$3
	verify_ip=$4
	is6=$5

	# 1. sysctl + pfctl — one-time: inject pass quick before com.apple/* anchor
	if ! /sbin/pfctl -sr 2>/dev/null | grep -qF "pass out quick on ${ifname}"; then
		/usr/sbin/sysctl -w net.inet.ip.forwarding=1 >/dev/null 2>&1
		/sbin/pfctl -f - 2>/dev/null <<-PFEOF
			scrub-anchor "com.apple/*"
			nat-anchor "com.apple/*"
			rdr-anchor "com.apple/*"
			dummynet-anchor "com.apple/*"
			pass out quick on ${ifname} inet proto { udp, icmp } from any to ${pfx}0/24 keep state
			anchor "com.apple/*"
		PFEOF
	fi

	# 2. add v4 subnet route (idempotent — already-exists is fine)
	/sbin/route -q -n add -net "${pfx}0/24" -interface "${ifname}" 2>/dev/null || true

	# 3. if v6, also add a host route for this addr
	if [ "$is6" = "6" ]; then
		if ! /sbin/route -q -n add -inet6 "${verify_ip}" -interface "${ifname}" 2>&1; then
			echo "route: add -inet6 ${verify_ip} via ${ifname} failed"
			exit 2
		fi
	fi

	# 4. verify that route get points to our interface
	if [ "$is6" = "6" ]; then
		rget=$(/sbin/route -n get -inet6 "${verify_ip}" 2>&1) || {
			echo "route: get -inet6 ${verify_ip} failed"
			echo "$rget"
			exit 3
		}
	else
		rget=$(/sbin/route -n get "${verify_ip}" 2>&1) || {
			echo "route: get ${verify_ip} failed"
			echo "$rget"
			exit 3
		}
	fi
	if ! echo "$rget" | grep -qE "(interface|gateway): ${ifname}"; then
		echo "route: verify FAIL ${verify_ip} — expected ${ifname}"
		echo "$rget"
		exit 4
	fi

	echo "route: verify OK ${verify_ip} via ${ifname}"
	;;
cleanup)
	/sbin/route -q -n delete -net "${pfx}0/24" 2>/dev/null || true
	echo "route: cleanup done"
	;;
*)
	echo "Usage: $0 setup <ifname> <vlanpfx> <verify_ip> <is6> | cleanup"
	exit 1
	;;
esac
