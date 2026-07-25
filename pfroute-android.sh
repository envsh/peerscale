


# 验证
cat /proc/sys/net/ipv4/conf/all/rp_filter  # 应为 0

cat /proc/sys/net/ipv4/conf/utun3/rp_filter  # 应为 0

cat  /proc/sys/net/ipv4/conf/all/accept_local # 应为 1

cat  /proc/sys/net/ipv4/conf/utun3/accept_local # 应为 1


# 设置
# Android netd 在优先级 10000+ 插入的规则可能绕过 TUN 路由。经典确认案例：linuxdeploy + OpenVPN 用户报告 "tun0 RX=0"，最终解决方案是：

# ip rule add from all lookup main pref 1
