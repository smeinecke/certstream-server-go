// Package tmpip implements tmpiprest-style source IPv6 rotation: outgoing
// connections are bound to a random address inside routed prefixes, giving
// each connection a fresh source IP - useful when the remote side rate-limits
// per source address.
package tmpip

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// LoadPools parses a tmpiprest.conf file into rotation pools. Device
// prefixes may carry a trailing ':' or '::' (as written for tmpip.py); mask
// defaults to 48. Ignore lists are skipped - in a >= /56 the collision
// probability with a configured address is negligible.
func LoadPools(path string) ([]*net.IPNet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var conf struct {
		Devices []struct {
			Prefix string `json:"prefix"`
			If     string `json:"if"`
			Mask   int    `json:"mask"`
		} `json:"Devices"`
	}
	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, err
	}
	var pools []*net.IPNet
	for _, d := range conf.Devices {
		mask := d.Mask
		if mask == 0 {
			mask = 48
		}
		_, pfx, err := net.ParseCIDR(strings.TrimRight(d.Prefix, ":") + "::/" + strconv.Itoa(mask))
		if err != nil {
			return nil, fmt.Errorf("tmpip device %q: %w", d.If, err)
		}
		pools = append(pools, pfx)
	}
	if len(pools) == 0 {
		return nil, fmt.Errorf("no Devices in %s", path)
	}
	return pools, nil
}

// CheckPools refuses prefixes narrower than /64 - per-IP rate limits may
// aggregate at that granularity, making rotation pointless.
func CheckPools(pools []*net.IPNet) error {
	for _, pfx := range pools {
		if ones, _ := pfx.Mask.Size(); ones > 64 {
			return fmt.Errorf("rotation prefix %s is narrower than /64 - refusing (per-IP rate limits may aggregate)", pfx)
		}
	}
	return nil
}

// RandIPv6 returns a random IPv6 address within prefix, preserving the
// network bits and randomizing the host bits.
func RandIPv6(prefix *net.IPNet) net.IP {
	ones, _ := prefix.Mask.Size()
	base := prefix.IP.To16()
	ip := make(net.IP, 16)
	for i := 0; i < 16; i++ {
		pbits := ones - i*8
		if pbits <= 0 {
			ip[i] = byte(rand.Uint32())
		} else if pbits >= 8 {
			ip[i] = base[i]
		} else {
			mask := byte(0xFF << (8 - pbits))
			ip[i] = (base[i] & mask) | (byte(rand.Uint32()) &^ mask)
		}
	}
	return ip
}

// RotatingDialContext returns a DialContext that binds each connection to a
// fresh random IPv6 source address, picked uniformly across pools. Forces
// tcp6 - the target must have a AAAA record when rotation is used.
func RotatingDialContext(pools []*net.IPNet) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := &net.Dialer{
			LocalAddr: &net.TCPAddr{IP: RandIPv6(pools[rand.Intn(len(pools))])},
			Timeout:   15 * time.Second,
		}
		return d.DialContext(ctx, "tcp6", addr)
	}
}

// DialTarget dials host:port preferring tcp6 with a rotating source address
// from pools; falls back to plain tcp when the target has no AAAA record or
// pools is empty.
func DialTarget(ctx context.Context, addr string, pools []*net.IPNet) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port = addr, "443"
	}
	has6 := false
	if ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host); err == nil {
		for _, ip := range ips {
			if ip.To4() == nil {
				has6 = true
				break
			}
		}
	}
	if has6 && len(pools) > 0 {
		d := &net.Dialer{
			LocalAddr: &net.TCPAddr{IP: RandIPv6(pools[rand.Intn(len(pools))])},
			Timeout:   15 * time.Second,
		}
		return d.DialContext(ctx, "tcp6", net.JoinHostPort(host, port))
	}
	d := &net.Dialer{Timeout: 15 * time.Second}
	return d.DialContext(ctx, "tcp", addr)
}
