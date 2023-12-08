/*
 *  Copyright (c) 2023 Neil Alexander
 *
 *  This Source Code Form is subject to the terms of the Mozilla Public
 *  License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package yggquic

import (
	"encoding/hex"
	"io"
	"net"
	"testing"

	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
)

func TestQUICOverYggdrasil(t *testing.T) {
	cfg1 := config.GenerateConfig()
	cfg2 := config.GenerateConfig()

	// Create the Yggdrasil nodes.
	node1, err := core.New(cfg1.Certificate, nil)
	if err != nil {
		t.Fatal(err)
	}
	node2, err := core.New(cfg2.Certificate, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Peer the Yggdrasil nodes to each other.
	l, r := net.Pipe()
	go node1.HandleConn(node2.PublicKey(), l, 0) // nolint:errcheck
	go node2.HandleConn(node1.PublicKey(), r, 0) // nolint:errcheck

	// Create QUIC over Yggdrasil endpoints.
	quic1, err := New(node1, *cfg1.Certificate, nil)
	if err != nil {
		t.Fatal(err)
	}
	quic2, err := New(node2, *cfg2.Certificate, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Dial node 1 from node 2.
	t.Run("Dial", func(t *testing.T) {
		t.Parallel()

		destination := hex.EncodeToString(node1.PublicKey())
		c, err := quic2.Dial("yggdrasil", destination)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("Opened connection to %q", c.RemoteAddr().String())
		if _, err = c.Write([]byte("Hello!")); err != nil {
			t.Fatal(err)
		}
		if err = c.Close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Listen", func(t *testing.T) {
		t.Parallel()

		c, err := quic1.Accept()
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("Accepted connection from %q", c.RemoteAddr())

		b, err := io.ReadAll(c)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("Received: %s", b[:])
	})
}
