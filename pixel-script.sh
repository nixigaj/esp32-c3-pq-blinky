#!/system/bin/sh

until [ "$(getprop sys.boot_completed)" = "1" ]; do
    sleep 2
done

STATIC_GW="192.168.43.1/24"
STATIC_SUBNET="192.168.43.0/24"

echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null
echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects 2>/dev/null

while true; do
    for IFACE in ap_br_wlan2 wlan2; do
        if ip -4 addr show dev "$IFACE" 2>/dev/null | grep -q "inet "; then
            if ! ip -4 addr show dev "$IFACE" 2>/dev/null | grep -q "192.168.43.1/"; then
                ip addr add "$STATIC_GW" brd 192.168.43.255 dev "$IFACE"

                # Disable rp_filter & ICMP redirects (requires both all and per-iface in Linux IN_DEV_ORCONF)
                echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null
                echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects 2>/dev/null
                echo 0 > "/proc/sys/net/ipv4/conf/$IFACE/rp_filter" 2>/dev/null
                echo 0 > "/proc/sys/net/ipv4/conf/$IFACE/send_redirects" 2>/dev/null

                # Ensure link route exists in built-in table 'main' (254), which also holds the 10.x.y.0/24 link route
                ip route replace "$STATIC_SUBNET" dev "$IFACE" scope link src 192.168.43.1 table main 2>/dev/null

                # Route both directions (host -> 192.168.43.0/24 and 192.168.43.0/24 -> host) via table 'main'
                while ip rule del to "$STATIC_SUBNET" lookup main pref 9000 2>/dev/null; do :; done
                while ip rule del from "$STATIC_SUBNET" lookup main pref 9000 2>/dev/null; do :; done
                ip rule add to "$STATIC_SUBNET" lookup main pref 9000
                ip rule add from "$STATIC_SUBNET" lookup main pref 9000

                iptables -C tetherctrl_FORWARD -i "$IFACE" -o "$IFACE" -j ACCEPT 2>/dev/null || \
                    iptables -I tetherctrl_FORWARD -i "$IFACE" -o "$IFACE" -j ACCEPT
                iptables -C FORWARD -i "$IFACE" -o "$IFACE" -j ACCEPT 2>/dev/null || \
                    iptables -I FORWARD -i "$IFACE" -o "$IFACE" -j ACCEPT
            fi
        fi
    done
    sleep 3
done
