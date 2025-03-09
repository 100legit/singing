#!/bin/sh

NFTABLES_TABLE="proxy4"
CN_CIDR_FILE="/etc/cn_cidr.nft"

download_cn_cidr() {
    curl -s -L https://ispip.clang.cn/all_cn_cidr.txt \
        | sed -e '$!s/$/,/' \
        | sed -e '1s/^/define CN_CIDR_4 = {\n/' \
        | sed -e '$a}' \
        > "$CN_CIDR_FILE"

    if [ $? -ne 0 ]; then
        echo "ERROR: Unable to download CN CIDR list." >&2
        return 1
    fi
    return 0
}

create_nftables_rules() {
    nft delete table ip "$NFTABLES_TABLE" 2>/dev/null

    nft -f - <<EOF
include "$CN_CIDR_FILE"

table ip $NFTABLES_TABLE {
    set intranet {
        typeof ip daddr
        flags interval
        elements = {
            0.0.0.0/8,
            10.0.0.0/8,
            127.0.0.0/8,
            169.254.0.0/16,
            172.16.0.0/12,
            192.168.0.0/16,
            224.0.0.0/4,
            240.0.0.0/4,
        }
    }
    set chnroute {
        typeof ip daddr
        flags interval
        elements = \$CN_CIDR_4
    }
    set static_ip {
        typeof ip saddr
        flags interval
        comment "generated from openwrt dhcp"
    }
    set static_ip_mac {
        type ether_addr
        flags interval
        comment "generated from openwrt dhcp"
    }
    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;

        ip protocol udp udp dport 53 tproxy to 127.0.0.1:1536 meta mark set 1

        ip daddr @intranet return
        ip daddr @chnroute return

        ip protocol tcp tproxy to 127.0.0.1:1536 meta mark set 1
        ip protocol udp tproxy to 127.0.0.1:1536 meta mark set 1
    }
}
EOF

    if [ $? -ne 0 ]; then
        echo "ERROR: Failed to create nftables rules." >&2
        return 1
    fi

    local i=0
    while uci -q get "dhcp.@host[${i}]" &> /dev/null; do
        local mac=$(uci -q get "dhcp.@host[${i}].mac")
        local ip=$(uci -q get "dhcp.@host[${i}].ip")

        if [ -n "$mac" ] && [ -n "$ip" ]; then
          nft add element ip "$NFTABLES_TABLE" static_ip_mac "{ $mac }"
          nft add element ip "$NFTABLES_TABLE" static_ip "{ $ip }"
        fi
        i=$((i+1))
    done

    return 0
}

setup_routing() {
    ip rule add fwmark 0x1 table 100
    ip route add local default dev lo table 100
}

cleanup_routing() {
    ip rule del table 100 || true
    ip route del local default dev lo table 100 || true
}

cleanup_nftables() {
    nft delete table ip "$NFTABLES_TABLE" || true
}
cleanup_all(){
    cleanup_routing
    cleanup_nftables
    service dnsmasq reload
}

case "$1" in
    start)
        create_nftables_rules && setup_routing
        #create_nftables_rules
        ;;
    stop)
        cleanup_all
        #cleanup_nftables
        ;;
    *)
        echo "Usage: $0 {start|stop}"
        exit 1
        ;;
esac

exit 0
