package main

import (
	"log"
	"net"
	"sync"
	"time"
)

var (
	localIPsMu    sync.RWMutex
	localIPsSet   map[string]bool
	localIPsReady bool
)

// initLocalIPs discovers the host's IP addresses and caches them.
// It should be called once at startup. Safe to call multiple times;
// subsequent calls refresh the cache.
func initLocalIPs() {
	ips := make(map[string]bool)

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Printf("⚠️  net.InterfaceAddrs failed: %v", err)
	} else {
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			if ip.IsLoopback() {
				continue
			}
			if ip.IsLinkLocalUnicast() {
				continue
			}
			// Normalize to the canonical string form
			ips[ip.String()] = true
		}
	}

	localIPsMu.Lock()
	localIPsSet = ips
	localIPsReady = true
	localIPsMu.Unlock()

	log.Printf("🌐 Discovered %d local IP(s):", len(ips))
	for ip := range ips {
		log.Printf("     %s", ip)
	}
}

// startLocalIPsRefresh spawns a background goroutine that refreshes
// the local IP set every interval. Use when interfaces may change
// during runtime (VPN, DHCP renewals, container attach).
func startLocalIPsRefresh(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			initLocalIPs()
		}
	}()
}

// isLocalIP reports whether ip (as a string) belongs to this host.
func isLocalIP(ip string) bool {
	localIPsMu.RLock()
	defer localIPsMu.RUnlock()

	if !localIPsReady {
		return false
	}
	return localIPsSet[ip]
}
