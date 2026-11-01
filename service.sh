#!/system/bin/sh

TUN_NAME=tun0

# Mark used to pull traffic into the tun table. Only $FWMASK bits are touched,
# so Android's own fwmark bits (netId, permissions, ...) are preserved.
# Change it if it ever clashes with another module.
FWMARK=0x40000000
FWMASK=0x40000000

# Client source ranges that get marked.
SRC_V4="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
# fc00::/7 = ULA, 2000::/3 = global unicast (hotspot clients that were handed
# a delegated global prefix). Link-local / multicast are never marked.
SRC_V6="fc00::/7 2000::/3"

# Destinations that are never sent into the tun (intranet / special-use).
# Same lists as the Magic V2Ray service. Both the mangle chain (no mark) and
# policy routing (`to <cidr> lookup main`) use them.
LAN_BYPASS_V4="
10.0.0.0/8
100.64.0.0/10
127.0.0.0/8
169.254.0.0/16
172.16.0.0/12
192.0.0.0/24
192.0.2.0/24
192.88.99.0/24
192.168.0.0/16
198.51.100.0/24
203.0.113.0/24
224.0.0.0/4
240.0.0.0/4
255.255.255.255/32
"
LAN_BYPASS_V6="
::1/128
::ffff:0:0/96
64:ff9b::/96
100::/64
2001::/32
2001:10::/28
2001:20::/28
2001:db8::/32
2002::/16
fc00::/7
fe80::/10
ff00::/8
"

# Resolver that client IPv4 DNS (udp/53) is redirected to.
DNS_V4=1.1.1.1

RT_TABLES=/data/misc/net/rt_tables

CHAIN_MARK=VPNGW_MARK        # mangle PREROUTING, both families
CHAIN_DNS6=VPNGW_DNS6        # ip6tables filter INPUT/FORWARD

PREF_LO=5000
PREF_TUN_MAIN=5010
PREF_TUN_SKIP=5020
PREF_LAN=5025
PREF_MARK=5030
PREF_MARK_FAILCLOSED=5031    # IPv6 only
PREF_END=6000

ip="/system/bin/ip"
iptables="/system/bin/iptables"
ip6tables="/system/bin/ip6tables"

if [[ ! -x $ip ]] || [[ ! -x $iptables ]]; then
    echo "command 'ip' or 'iptables' not found"
    exit 1
fi

IPV6=1
if [[ ! -x $ip6tables ]]; then
    echo "command 'ip6tables' not found, IPv6 support disabled"
    IPV6=0
fi

# -w: wait for the xtables lock instead of failing while netd holds it.
ipt4="$iptables -w"
ipt6="$ip6tables -w"

# Helpers

# Prints the routing-table index netd registered for an interface name.
# (No `cat | while`: that runs in a subshell and loses the return value.)
function read_table_index() {
    local iface=$1 index name

    [[ -r $RT_TABLES ]] || return 1

    while read -r index name; do
        if [[ "$name" = "$iface" ]] && [[ -n "$index" ]]; then
            echo $index
            return 0
        fi
    done < $RT_TABLES

    return 1
}

# Policy-routing rules shared by both families.
function ip_rules_for() {
    local tun_table_index=$1

    cat <<EOF
iif lo goto $PREF_END pref $PREF_LO
iif $TUN_NAME lookup main suppress_prefixlength 0 pref $PREF_TUN_MAIN
iif $TUN_NAME goto $PREF_END pref $PREF_TUN_SKIP
fwmark $FWMARK/$FWMASK lookup $tun_table_index pref $PREF_MARK
nop pref $PREF_END
EOF
}

# Deleted by pref, not by full spec, so a stale table index can never leave a
# rule behind. Loop-delete because a pref may have been added more than once.
function del_ip_rules() {
    local fam=$1 pref

    for pref in $PREF_LO $PREF_TUN_MAIN $PREF_TUN_SKIP $PREF_LAN $PREF_MARK \
                $PREF_MARK_FAILCLOSED $PREF_END; do
        while $ip $fam rule del pref $pref 2>/dev/null; do :; done
    done
}

function add_ip_rules() {
    local fam=$1 tun_table_index=$2 bypass=$3 rule cidr

    ip_rules_for $tun_table_index | while read -r rule; do
        $ip $fam rule add $rule
    done

    # Intranet destinations use the normal tables (all share one pref so
    # del_ip_rules wipes them with a loop).
    for cidr in $bypass; do
        $ip $fam rule add to $cidr lookup main pref $PREF_LAN
    done

    # IPv6 fail-closed: marked packets that the tun table cannot route
    # (VPN without an IPv6 default route) must not fall through to the real
    # uplink.
    if [[ "$fam" = "-6" ]]; then
        $ip -6 rule add fwmark $FWMARK/$FWMASK unreachable pref $PREF_MARK_FAILCLOSED
    fi
}

# iptables / ip6tables

# $1: iptables command ($ipt4 / $ipt6)   $2: client source ranges
# $3: destinations to leave unmarked      $4: "dns" = mark udp/53 before bypass
function setup_mark_chain() {
    local ipt=$1 srcs=$2 bypass=$3 dns=$4 src cidr

    # mangle PREROUTING: mark everything coming from clients
    $ipt -t mangle -N $CHAIN_MARK 2>/dev/null
    $ipt -t mangle -F $CHAIN_MARK
    $ipt -t mangle -A $CHAIN_MARK -i lo -j RETURN
    $ipt -t mangle -A $CHAIN_MARK -i $TUN_NAME -j RETURN
    # IPv4 DNS is DNAT'd to $DNS_V4 later (nat runs after mangle, routing runs
    # after nat), so it must be marked here even if the original resolver is a
    # LAN address; otherwise the redirected query would leave unmarked.
    if [[ "$dns" = "dns" ]]; then
        for src in $srcs; do
            $ipt -t mangle -A $CHAIN_MARK -s $src -p udp --dport 53 -j MARK --set-xmark $FWMARK/$FWMASK
        done
        $ipt -t mangle -A $CHAIN_MARK -p udp --dport 53 -m mark --mark $FWMARK/$FWMASK -j RETURN
    fi
    for cidr in $bypass; do
        $ipt -t mangle -A $CHAIN_MARK -d $cidr -j RETURN
    done
    for src in $srcs; do
        $ipt -t mangle -A $CHAIN_MARK -s $src -j MARK --set-xmark $FWMARK/$FWMASK
    done
    $ipt -t mangle -I PREROUTING 1 -j $CHAIN_MARK

    # filter FORWARD: allow marked traffic out of the tun, and replies back in
    $ipt -I FORWARD -m mark --mark $FWMARK/$FWMASK -o $TUN_NAME -j ACCEPT
    $ipt -I FORWARD -i $TUN_NAME -j ACCEPT
}

function cleanup_mark_chain() {
    local ipt=$1

    while $ipt -t mangle -D PREROUTING -j $CHAIN_MARK 2>/dev/null; do :; done
    $ipt -t mangle -F $CHAIN_MARK 2>/dev/null
    $ipt -t mangle -X $CHAIN_MARK 2>/dev/null

    while $ipt -D FORWARD -m mark --mark $FWMARK/$FWMASK -o $TUN_NAME -j ACCEPT 2>/dev/null; do :; done
    while $ipt -D FORWARD -i $TUN_NAME -j ACCEPT 2>/dev/null; do :; done
}

# IPv4: force client DNS to $DNS_V4.
function setup_dns_v4() {
    local cidr

    for cidr in $SRC_V4; do
        $ipt4 -t nat -I PREROUTING ! -i $TUN_NAME -s $cidr -p udp --dport 53 -j DNAT --to $DNS_V4
    done
}

function cleanup_dns_v4() {
    local cidr

    for cidr in $SRC_V4; do
        while $ipt4 -t nat -D PREROUTING ! -i $TUN_NAME -s $cidr -p udp --dport 53 -j DNAT --to $DNS_V4 2>/dev/null; do :; done
    done
}

# IPv6: does not support NAT on most stock kernel
# Workaround: reject client DNS (tcp/udp 53) so clients fail over to IPv4 DNS immediately.
function setup_dns_block_v6() {
    $ipt6 -N $CHAIN_DNS6 2>/dev/null
    $ipt6 -F $CHAIN_DNS6
    $ipt6 -A $CHAIN_DNS6 -i lo -j RETURN
    $ipt6 -A $CHAIN_DNS6 -i $TUN_NAME -j RETURN
    $ipt6 -A $CHAIN_DNS6 -p udp --dport 53 -j REJECT --reject-with icmp6-port-unreachable
    $ipt6 -A $CHAIN_DNS6 -p tcp --dport 53 -j REJECT --reject-with tcp-reset
    # Inserted last by setup(), so they end up above the ACCEPT rules.
    $ipt6 -I FORWARD 1 -j $CHAIN_DNS6
    $ipt6 -I INPUT 1 -j $CHAIN_DNS6
}

function cleanup_dns_block_v6() {
    while $ipt6 -D FORWARD -j $CHAIN_DNS6 2>/dev/null; do :; done
    while $ipt6 -D INPUT -j $CHAIN_DNS6 2>/dev/null; do :; done
    $ipt6 -F $CHAIN_DNS6 2>/dev/null
    $ipt6 -X $CHAIN_DNS6 2>/dev/null
}

# setup / cleanup

function cleanup() {
    # IPv4
    del_ip_rules ""
    cleanup_mark_chain "$ipt4"
    cleanup_dns_v4

    # IPv6
    if [[ $IPV6 = 1 ]]; then
        del_ip_rules "-6"
        cleanup_mark_chain "$ipt6"
        cleanup_dns_block_v6
    fi
}

function setup() {
    local tun_table_index=$1

    cleanup

    # IPv4
    setup_mark_chain "$ipt4" "$SRC_V4" "$LAN_BYPASS_V4" dns
    setup_dns_v4
    add_ip_rules "" $tun_table_index "$LAN_BYPASS_V4"

    # IPv6
    if [[ $IPV6 = 1 ]]; then
        setup_mark_chain "$ipt6" "$SRC_V6" "$LAN_BYPASS_V6"
        setup_dns_block_v6
        add_ip_rules "-6" $tun_table_index "$LAN_BYPASS_V6"
    fi
}

# IP forwarding
function lock_sysctl() {
    local target=$1 stub=$2
    echo 1 > $target
    echo 0 > $stub
    chown $(stat -c '%u:%g' $RT_TABLES) $stub
    chcon $(stat -Z -c '%C' $RT_TABLES) $stub
    mount -o bind $stub $target
}

# Main

while [[ ! -f $RT_TABLES ]]; do
    sleep 5
done

tun_table_index=$(read_table_index $TUN_NAME)
echo "Initialize: $TUN_NAME $tun_table_index (ipv6=$IPV6)"

if [[ ! -z "$tun_table_index" ]]; then
    setup $tun_table_index
fi

lock_sysctl /proc/sys/net/ipv4/ip_forward /dev/ip_forward_stub

if [[ $IPV6 = 1 ]]; then
    # Interfaces created later (hotspot AP) inherit "default".
    echo 1 > /proc/sys/net/ipv6/conf/default/forwarding
    lock_sysctl /proc/sys/net/ipv6/conf/all/forwarding /dev/ip6_forward_stub
fi

inotifyd - /data/misc/net::w | while read -r event; do
    sleep 1

    tun_table_index_new=$(read_table_index $TUN_NAME)
    if [[ "$tun_table_index" != "$tun_table_index_new" ]]; then
        echo "Network changed: $TUN_NAME $tun_table_index_new"

        tun_table_index=$tun_table_index_new

        if [[ ! -z "$tun_table_index" ]]; then
            setup $tun_table_index
        else
            cleanup
        fi
    fi
done
