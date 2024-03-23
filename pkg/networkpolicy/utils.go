package networkpolicy

import (
	"net"

	v1 "k8s.io/api/core/v1"
)

func getPodIPNets(podStatus v1.PodStatus) []string {
	addresses := []string{}

	for _, podIP := range podStatus.PodIPs {
		ipNet := ipToIPNet(podIP.String())
		addresses = append(addresses, ipNet.String())
	}

	return addresses
}

func ipToIPNet(address string) *net.IPNet {
	ip := net.ParseIP(address)
	maskLen := 128
	if ip.To4() != nil {
		maskLen = 32
	}
	return &net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(maskLen, maskLen),
	}
}
