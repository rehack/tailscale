// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package xdpderp

import (
	"errors"
	"fmt"
	"math"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type config -type stats_key -type stats_per_af bpf xdp.c -- -I headers

type STUNServer struct {
	mu   sync.Mutex
	objs bpfObjects
	// TODO(jwhited): export this
	stats *stunServerStats
}

type STUNServerConfig struct {
	DeviceName  string
	DstPort     int
	AttachFlags link.XDPAttachFlags
}

func (s *STUNServerConfig) validate() error {
	if len(s.DeviceName) < 1 {
		return errors.New("DeviceName is unspecified")
	}
	if s.DstPort < 0 || s.DstPort > math.MaxUint16 {
		return errors.New("DstPort is outside of uint16 bounds")
	}
	return nil
}

func NewSTUNServer(config *STUNServerConfig) (*STUNServer, error) {
	err := config.validate()
	if err != nil {
		return nil, fmt.Errorf("invalid config: %v", err)
	}
	iface, err := net.InterfaceByName(config.DeviceName)
	if err != nil {
		return nil, fmt.Errorf("error finding device: %w", err)
	}
	objs := bpfObjects{}
	err = loadBpfObjects(&objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSize: ebpf.DefaultVerifierLogSize * 10,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("error loading XDP program: %w", err)
	}
	server := &STUNServer{
		objs: objs,
	}
	var key uint32
	xdpConfig := bpfConfig{
		DstPort: uint16(config.DstPort),
	}
	err = objs.ConfigMap.Put(key, &xdpConfig)
	if err != nil {
		return nil, fmt.Errorf("error loading config in eBPF map: %w", err)
	}
	_, err = link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: iface.Index,
		Flags:     config.AttachFlags,
	})
	if err != nil {
		return nil, fmt.Errorf("error attaching XDP program to dev: %w", err)
	}
	return server, nil
}

func (s *STUNServer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.objs.Close()
}

type stunServerStats struct {
	packets *prometheus.GaugeVec
	bytes   *prometheus.GaugeVec
}

const (
	xdpOutcomeKey = "xdp_outcome"
)

const (
	xdpOutcomePass    = "pass"
	xdpOutcomeAborted = "aborted"
	xdpOutcomeDrop    = "drop"
	xdpOutcomeTX      = "tx"
)

func sumBpfStatsPerAf(vals []bpfStatsPerAf) bpfStatsPerAf {
	var sum bpfStatsPerAf
	for _, v := range vals {
		sum.Unknown += v.Unknown
		sum.Ipv4 += v.Ipv4
		sum.Ipv6 += v.Ipv6
	}
	return sum
}

const (
	addressFamilyKey = "address_family"
)

const (
	addressFamilyUnknown = "unknown"
	addressFamilyIPv4    = "ipv4"
	addressFamilyIPv6    = "ipv6"
)

var (
	statsKeyToOutcomeLabel = map[bpfStatsKey]string{
		bpfStatsKeySTAT_PACKETS_PASS_TOTAL:    xdpOutcomePass,
		bpfStatsKeySTAT_BYTES_PASS_TOTAL:      xdpOutcomePass,
		bpfStatsKeySTAT_PACKETS_ABORTED_TOTAL: xdpOutcomeAborted,
		bpfStatsKeySTAT_BYTES_ABORTED_TOTAL:   xdpOutcomeAborted,
		bpfStatsKeySTAT_PACKETS_TX_TOTAL:      xdpOutcomeTX,
		bpfStatsKeySTAT_BYTES_TX_TOTAL:        xdpOutcomeTX,
		bpfStatsKeySTAT_PACKETS_DROP_TOTAL:    xdpOutcomeDrop,
		bpfStatsKeySTAT_BYTES_DROP_TOTAL:      xdpOutcomeDrop,
	}

	packetsStatsKeys = map[bpfStatsKey]bool{
		bpfStatsKeySTAT_PACKETS_PASS_TOTAL:    true,
		bpfStatsKeySTAT_PACKETS_ABORTED_TOTAL: true,
		bpfStatsKeySTAT_PACKETS_TX_TOTAL:      true,
		bpfStatsKeySTAT_PACKETS_DROP_TOTAL:    true,
	}

	bytesStatsKeys = map[bpfStatsKey]bool{
		bpfStatsKeySTAT_BYTES_PASS_TOTAL:    true,
		bpfStatsKeySTAT_BYTES_ABORTED_TOTAL: true,
		bpfStatsKeySTAT_BYTES_TX_TOTAL:      true,
		bpfStatsKeySTAT_BYTES_DROP_TOTAL:    true,
	}
)

func (s *stunServerStats) updateFromMapKV(key uint32, vals []bpfStatsPerAf) error {
	outcomeLabel, ok := statsKeyToOutcomeLabel[bpfStatsKey(key)]
	if !ok {
		return fmt.Errorf("unexpected stats key in eBPF map: %d", key)
	}
	sum := sumBpfStatsPerAf(vals)
	var metric *prometheus.GaugeVec
	if packetsStatsKeys[bpfStatsKey(key)] {
		metric = s.packets
	} else if bytesStatsKeys[bpfStatsKey(key)] {
		metric = s.bytes
	} else {
		return fmt.Errorf("unexpected stats key in eBPF map: %d", key)
	}
	metric.With(prometheus.Labels{
		xdpOutcomeKey:    outcomeLabel,
		addressFamilyKey: addressFamilyUnknown,
	}).Set(float64(sum.Unknown))
	metric.With(prometheus.Labels{
		xdpOutcomeKey:    outcomeLabel,
		addressFamilyKey: addressFamilyIPv4,
	}).Set(float64(sum.Ipv4))
	metric.With(prometheus.Labels{
		xdpOutcomeKey:    outcomeLabel,
		addressFamilyKey: addressFamilyIPv6,
	}).Set(float64(sum.Ipv6))
	return nil
}

// TODO(jwhited): tick this
func (s *STUNServer) updateStats() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	iter := s.objs.StatsMap.Iterate()
	var key uint32
	numCPU, err := ebpf.PossibleCPU()
	if err != nil {
		return err
	}
	vals := make([]bpfStatsPerAf, numCPU)
	for iter.Next(&key, &vals) {
		err := s.stats.updateFromMapKV(key, vals)
		if err != nil {
			return err
		}
	}
	return iter.Err()
}
