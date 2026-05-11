// Copyright 2026 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"syscall"

	"github.com/vishvananda/netlink"

	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/netlinksafe"
	"github.com/containernetworking/plugins/pkg/ns"
)

const (
	localRouteTable  = 255
	ifaFlagPermanent = 0x80 // IFA_F_PERMANENT from linux/if_addr.h
)

// HostNetworkState holds the captured host-side L3 configuration
// (addresses, routes, and rules) that should be applied to the container interface.
// This struct is never serialized; it lives only for the duration of a single cmdAdd call.
type HostNetworkState struct {
	HostIfName    string
	HostLinkWasUp bool
	Addresses     []netlink.Addr
	Routes        []netlink.Route
	Rules         []netlink.Rule
}

func useInterfaceNetwork(conf *NetConf) bool {
	return conf != nil && conf.UseInterfaceNetwork
}

// newHostNetworkState creates a HostNetworkState from the given host device,
// capturing addresses, routes, and rules when captureNetwork is true.
func newHostNetworkState(hostDev netlink.Link, captureNetwork bool) (*HostNetworkState, error) {
	state := &HostNetworkState{
		HostIfName:    hostDev.Attrs().Name,
		HostLinkWasUp: hostDev.Attrs().Flags&net.FlagUp == net.FlagUp,
	}
	if captureNetwork {
		if err := captureHostNetworkState(state, hostDev); err != nil {
			return nil, err
		}
	}
	return state, nil
}

func captureHostNetworkState(state *HostNetworkState, hostDev netlink.Link) error {
	addrs, err := netlinksafe.AddrList(hostDev, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to list addresses for host device %s: %w", hostDev.Attrs().Name, err)
	}
	for _, addr := range addrs {
		if addr.Scope != int(netlink.SCOPE_UNIVERSE) || addr.IPNet == nil {
			continue
		}
		// Skip dynamic (SLAAC / DHCPv6) addresses: they are managed by the
		// kernel with a finite lifetime and there is no renewal daemon in
		// the container, so they would become stale permanent entries.
		if addr.Flags&ifaFlagPermanent == 0 {
			continue
		}
		state.Addresses = append(state.Addresses, addr)
	}

	filter := &netlink.Route{LinkIndex: hostDev.Attrs().Index, Table: syscall.RT_TABLE_UNSPEC}
	routes, err := netlinksafe.RouteListFiltered(netlink.FAMILY_ALL, filter, netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("failed to list routes for host device %s: %w", hostDev.Attrs().Name, err)
	}
	for _, route := range routes {
		if route.Table == localRouteTable {
			continue
		}
		if route.Protocol == syscall.RTPROT_KERNEL {
			continue
		}
		// Skip RA-learned routes: the kernel handles Router Advertisements
		// natively (accept_ra sysctl), so the container will receive fresh
		// RA routes with proper lifetimes once the interface is moved in.
		if route.Protocol == syscall.RTPROT_RA {
			continue
		}
		isDefaultRoute := route.Dst == nil
		if !isDefaultRoute && route.Dst.IP.To4() == nil {
			if route.Dst.IP.IsLinkLocalUnicast() {
				continue
			}
		}
		state.Routes = append(state.Routes, route)
	}

	rules, err := netlinksafe.RuleList(netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to list rules: %w", err)
	}
	for _, rule := range rules {
		if rule.Src == nil {
			continue
		}
		if rule.Table == 0 || rule.Table == localRouteTable {
			continue
		}
		state.Rules = append(state.Rules, rule)
	}

	return nil
}

func (state *HostNetworkState) applyToPod(containerNs ns.NetNS, contDev netlink.Link) error {
	if state == nil {
		return nil
	}
	return containerNs.Do(func(_ ns.NetNS) error {
		return state.applyOnLink(contDev)
	})
}

func (state *HostNetworkState) applyOnLink(link netlink.Link) error {
	if state == nil {
		return nil
	}
	linkIndex := link.Attrs().Index

	for _, addr := range state.Addresses {
		if err := ignoreExists(netlink.AddrAdd(link, &netlink.Addr{IPNet: addr.IPNet})); err != nil {
			return fmt.Errorf("failed to add copied address %v on %s: %w", addr.IPNet, link.Attrs().Name, err)
		}
	}

	orderedRoutes := make([]netlink.Route, len(state.Routes))
	copy(orderedRoutes, state.Routes)
	sort.SliceStable(orderedRoutes, func(i, j int) bool {
		return orderedRoutes[i].Scope > orderedRoutes[j].Scope
	})
	for _, route := range orderedRoutes {
		route.LinkIndex = linkIndex
		if err := ignoreExists(netlink.RouteAdd(&route)); err != nil {
			return fmt.Errorf("failed to add copied route %v on %s: %w", route, link.Attrs().Name, err)
		}
	}

	for _, rule := range state.Rules {
		if err := ignoreExists(netlink.RuleAdd(&rule)); err != nil {
			return fmt.Errorf("failed to add copied rule (src=%v table=%d): %w", rule.Src, rule.Table, err)
		}
	}

	return nil
}

// ignoreExists returns nil when err is EEXIST, otherwise returns err unchanged.
func ignoreExists(err error) error {
	if errors.Is(err, syscall.EEXIST) {
		return nil
	}
	return err
}

func routeToCNIRoute(route netlink.Route) *types.Route {
	var dst net.IPNet
	if route.Dst == nil {
		dst = net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
		if route.Gw != nil && route.Gw.To4() == nil {
			dst = net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
		}
	} else {
		dst = *route.Dst
	}

	cniRoute := &types.Route{Dst: dst, GW: route.Gw, Priority: route.Priority}
	if route.Table != 0 {
		cniRoute.Table = current.Int(route.Table)
	}
	if route.Scope != 0 {
		cniRoute.Scope = current.Int(int(route.Scope))
	}
	return cniRoute
}
