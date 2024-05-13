// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"tailscale.com/xdpderp"
)

var (
	flagDevice  = flag.String("device", "", "target device name")
	flagPort    = flag.Int("dst-port", 0, "destination UDP port to serve")
	flagVerbose = flag.Bool("verbose", false, "verbose output including verifier errors")
	flagMode    = flag.String("mode", "xdp", "XDP mode; valid modes: [xdp, xdpgeneric, xdpdrv, xdpoffload]")
)

func main() {
	flag.Parse()
	var attachFlags link.XDPAttachFlags
	switch strings.ToLower(*flagMode) {
	case "xdp":
		attachFlags = 0
	case "xdpgeneric":
		attachFlags = link.XDPGenericMode
	case "xdpdrv":
		attachFlags = link.XDPDriverMode
	case "xdpoffload":
		attachFlags = link.XDPOffloadMode
	default:
		log.Fatal("invalid mode")
	}
	server, err := xdpderp.NewSTUNServer(&xdpderp.STUNServerConfig{
		DeviceName:  *flagDevice,
		DstPort:     *flagPort,
		AttachFlags: attachFlags,
	})
	if err != nil {
		ve := &ebpf.VerifierError{}
		if *flagVerbose && errors.As(err, &ve) {
			log.Fatalf("%+v", ve)
		}
		log.Fatal(err)
	}
	defer server.Close()
	log.Println("XDP STUN server started")

	// TODO: exports stats

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
