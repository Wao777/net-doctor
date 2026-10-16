# -*- coding: utf-8 -*-
"""修复动作 id 常量表。

扫描器（scanner）只引用这里的常量来挂接修复动作，
真正的执行体在 fixers.py 中实现，两边通过常量对齐，避免拼写漂移。
"""
from __future__ import annotations

# ---- 稳健档（FIX_MODE_SAFE）：可逆、无需重启、无副作用 ----
FIX_DNS_FLUSH = "fix.dns.flush"            # 清空 DNS 解析缓存
FIX_DNS_REGISTER = "fix.dns.register"      # 重新注册本机 DNS 记录
FIX_DNS_SET_PUBLIC = "fix.dns.setpublic"   # DNS 改为公共 DNS（可选、可回滚）
FIX_DHCP_RENEW = "fix.dhcp.renew"          # 释放并重新获取 IP 租约
FIX_DHCP_AUTO = "fix.dhcp.auto"            # 把网卡切回 DHCP 自动获取
FIX_PROXY_DISABLE = "fix.proxy.disable"    # 关闭系统代理 / 清理 PAC / winhttp 代理
FIX_ENV_PROXY_CLEAR = "fix.proxy.env"      # 清理 HTTP(S)_PROXY 环境变量
FIX_HOSTS_RESTORE = "fix.hosts.restore"    # 还原 hosts 到系统默认
FIX_SERVICE_START = "fix.service.start"    # 启动并设为自动：关键网络服务
FIX_ADAPTER_RESTART = "fix.adapter.restart"  # 禁用后重新启用网卡
FIX_ARP_FLUSH = "fix.arp.flush"            # 清空 ARP 缓存
FIX_NETBIOS_RESET = "fix.netbios.reset"    # 重置 NetBIOS 名称缓存
FIX_MTU_RESET = "fix.mtu.reset"            # MTU 恢复标准 1500
FIX_ROUTE_REFRESH = "fix.route.refresh"    # 删除异常默认路由并重新获取
FIX_POWERSAVE_OFF = "fix.powersave.off"    # 关闭网卡节能断流
FIX_TIME_SYNC = "fix.time.sync"            # 校时（证书错误导致"假断网"）

# ---- 进阶档（FIX_MODE_ADVANCED）：影响面较大，需二次确认，可能需重启 ----
FIX_WINSOCK_RESET = "fix.winsock.reset"    # 重置 Winsock 目录
FIX_TCPIP_RESET = "fix.tcpip.reset"        # 重置 TCP/IP 协议栈
FIX_ADVFW_RESET = "fix.firewall.reset"     # 重置 Windows 防火墙策略

# 关键网络服务（显示名 -> 服务名）
CRITICAL_SERVICES = [
    ("DHCP Client", "Dhcp"),
    ("DNS Client", "Dnscache"),
    ("Network Connections", "Netman"),
    ("Network Location Awareness", "NlaSvc"),
    ("Network Store Interface Service", "nsi"),
    ("Network List Service", "netprofm"),
    ("Remote Procedure Call (RPC)", "RpcSs"),
    ("WLAN AutoConfig", "WlanSvc"),          # 仅无线网卡存在时校验
]
WIRELESS_SERVICE = "WlanSvc"

# 这些服务应当常驻运行，停止即视为异常；
# 其余服务为「按需启动」，停止本身不一定是故障（仅断网时才提示）。
ALWAYS_ON_SERVICES = {"Dhcp", "Dnscache", "nsi", "RpcSs"}


# 常见公共 DNS（供"DNS 不可达"时推荐/一键切换）
PUBLIC_DNS = [("223.5.5.5", "223.6.6.6"), ("119.29.29.29", "119.28.28.28"),
              ("114.114.114.114", "114.114.115.115")]

# 系统 hosts 默认内容（Windows 出厂模板）
DEFAULT_HOSTS = """# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#\t127.0.0.1       localhost
#\t::1             localhost
"""
