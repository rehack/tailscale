// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/mdlayher/socket"
	"golang.org/x/sys/unix"
	"tailscale.com/net/stun"
)

const (
	flags = unix.SOF_TIMESTAMPING_TX_SOFTWARE | // tx timestamp generation in device driver
		unix.SOF_TIMESTAMPING_RX_SOFTWARE | // rx timestamp generation in the kernel
		unix.SOF_TIMESTAMPING_SOFTWARE // report software timestamps
)

func getConnKernelTimestamp() (io.ReadWriteCloser, error) {
	sconn, err := socket.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP, "udp", nil)
	if err != nil {
		return nil, err
	}
	sa := unix.SockaddrInet6{}
	err = sconn.Bind(&sa)
	if err != nil {
		return nil, err
	}
	err = sconn.SetsockoptInt(unix.SOL_SOCKET, unix.SO_TIMESTAMPING_NEW, flags)
	if err != nil {
		return nil, err
	}
	return sconn, nil
}

func parseTimestampFromCmsgs(oob []byte) (time.Time, error) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return time.Time{}, fmt.Errorf("error parsing oob as cmsgs: %w", err)
	}
	for _, msg := range msgs {
		if msg.Header.Level == unix.SOL_SOCKET && msg.Header.Type == unix.SO_TIMESTAMPING_NEW && len(msg.Data) >= 16 {
			sec := int64(binary.NativeEndian.Uint64(msg.Data[:8]))
			ns := int64(binary.NativeEndian.Uint64(msg.Data[8:16]))
			return time.Unix(sec, ns), nil
		}
	}
	return time.Time{}, errors.New("failed to parse timestamp from cmsgs")
}

func measureRTTKernel(conn io.ReadWriteCloser, dst *net.UDPAddr) (rtt time.Duration, err error) {
	sconn, ok := conn.(*socket.Conn)
	if !ok {
		return 0, fmt.Errorf("conn of unexpected type: %T", conn)
	}

	var to unix.Sockaddr
	to4 := dst.IP.To4()
	if to4 != nil {
		to = &unix.SockaddrInet4{
			Port: dst.Port,
		}
		copy(to.(*unix.SockaddrInet4).Addr[:], to4)
	} else {
		to = &unix.SockaddrInet6{
			Port: dst.Port,
		}
		copy(to.(*unix.SockaddrInet6).Addr[:], dst.IP)
	}

	txID := stun.NewTxID()
	req := stun.Request(txID)

	err = sconn.Sendto(context.Background(), req, 0, to)
	if err != nil {
		return 0, fmt.Errorf("sendto error: %v", err) // don't wrap
	}

	txCtx, txCancel := context.WithTimeout(context.Background(), time.Second*2)
	defer txCancel()

	buf := make([]byte, 1024)
	oob := make([]byte, 1024)
	var txAt time.Time

	for {
		n, oobn, _, _, err := sconn.Recvmsg(txCtx, buf, oob, unix.MSG_ERRQUEUE)
		if err != nil {
			return 0, fmt.Errorf("recvmsg (MSG_ERRQUEUE) error: %v", err) // don't wrap
		}

		buf = buf[:n]
		if n < len(req) || !bytes.Equal(req, buf[len(buf)-len(req):]) {
			// Spin until we find the message we sent. We get the full packet
			// looped including eth header so match against the tail.
			continue
		}
		txAt, err = parseTimestampFromCmsgs(oob[:oobn])
		if err != nil {
			return 0, fmt.Errorf("failed to get tx timestamp: %v", err) // don't wrap
		}
		break
	}

	rxCtx, rxCancel := context.WithTimeout(context.Background(), time.Second*2)
	defer rxCancel()

	for {
		n, oobn, _, _, err := sconn.Recvmsg(rxCtx, buf, oob, 0)
		if err != nil {
			return 0, fmt.Errorf("recvmsg error: %w", err) // wrap for timeout-related error unwrapping
		}

		gotTxID, _, err := stun.ParseResponse(buf[:n])
		if err != nil || gotTxID != txID {
			// Spin until we find the txID we sent. We may end up reading
			// extremely late arriving responses from previous intervals. As
			// such, we can't be certain if we're parsing the "current"
			// response, so spin for parse errors too.
			continue
		}

		rxAt, err := parseTimestampFromCmsgs(oob[:oobn])
		if err != nil {
			return 0, fmt.Errorf("failed to get rx timestamp: %v", err) // don't wrap
		}

		return rxAt.Sub(txAt), nil
	}

}

func supportsKernelTS() bool {
	return true
}
