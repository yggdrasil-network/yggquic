/*
 *  Copyright (c) 2023 Neil Alexander
 *
 *  This Source Code Form is subject to the terms of the Mozilla Public
 *  License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package yggquic

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"

	iwt "github.com/Arceliar/ironwood/types"
	"github.com/quic-go/quic-go"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
)

type YggdrasilTransport struct {
	yggdrasil  net.PacketConn
	listener   *quic.Listener
	transport  *quic.Transport
	tlsConfig  *tls.Config
	quicConfig *quic.Config
	incoming   chan *yggdrasilSession
	sessions   sync.Map // string -> quic.Connection
	dials      sync.Map // string -> *yggdrasilDial
}

type yggdrasilSession struct {
	quic.Connection
	quic.Stream
}

type yggdrasilDial struct {
	context.Context
	context.CancelFunc
}

func New(ygg *core.Core, cert tls.Certificate) (*YggdrasilTransport, error) {
	tr := &YggdrasilTransport{
		tlsConfig: &tls.Config{
			ServerName:         hex.EncodeToString(ygg.PublicKey()),
			Certificates:       []tls.Certificate{cert},
			InsecureSkipVerify: true,
		},
		quicConfig: &quic.Config{
			HandshakeIdleTimeout: time.Second * 5,
			MaxIdleTimeout:       time.Second * 60,
		},
		transport: &quic.Transport{
			Conn: ygg,
		},
		yggdrasil: ygg,
		incoming:  make(chan *yggdrasilSession, 1),
	}

	var err error
	if tr.listener, err = tr.transport.Listen(tr.tlsConfig, tr.quicConfig); err != nil {
		return nil, fmt.Errorf("quic.Listen: %w", err)
	}

	go tr.connectionAcceptLoop()
	return tr, nil
}

func (t *YggdrasilTransport) connectionAcceptLoop() {
	for {
		qc, err := t.listener.Accept(context.TODO())
		if err != nil {
			return
		}

		host := qc.RemoteAddr().String()
		if eqc, ok := t.sessions.LoadAndDelete(host); ok {
			eqc := eqc.(quic.Connection)
			_ = eqc.CloseWithError(0, "Connection replaced")
		}
		t.sessions.Store(host, qc)
		if dial, ok := t.dials.LoadAndDelete(host); ok {
			dial := dial.(*yggdrasilDial)
			dial.CancelFunc()
		}

		go t.streamAcceptLoop(qc)
	}
}

func (t *YggdrasilTransport) streamAcceptLoop(qc quic.Connection) {
	host := qc.RemoteAddr().String()

	defer qc.CloseWithError(0, "Timed out") // nolint:errcheck
	defer t.sessions.Delete(host)

	for {
		qs, err := qc.AcceptStream(context.Background())
		if err != nil {
			break
		}
		t.incoming <- &yggdrasilSession{qc, qs}
	}
}

func (t *YggdrasilTransport) Dial(network, host string) (net.Conn, error) {
	return t.DialContext(context.TODO(), network, host)
}

func (t *YggdrasilTransport) DialContext(ctx context.Context, network, host string) (net.Conn, error) {
	if network != "yggdrasil" {
		return nil, fmt.Errorf("network must be 'yggdrasil'")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()
	var retry bool
retry:
	qc, ok := t.sessions.Load(host)
	if !ok {
		if dial, ok := t.dials.Load(host); ok {
			<-dial.(*yggdrasilDial).Done()
		}
		if qc, ok = t.sessions.Load(host); !ok {
			dialctx, dialcancel := context.WithCancel(ctx)
			defer dialcancel()

			t.dials.Store(host, &yggdrasilDial{dialctx, dialcancel})
			defer t.dials.Delete(host)

			addr := make(iwt.Addr, ed25519.PublicKeySize)
			k, err := hex.DecodeString(host)
			if err != nil {
				return nil, err
			}
			copy(addr, k)

			if qc, err = t.transport.Dial(dialctx, addr, t.tlsConfig, t.quicConfig); err != nil {
				return nil, err
			}

			qc := qc.(quic.Connection)
			t.sessions.Store(host, qc)
			go t.streamAcceptLoop(qc)
		}
	}
	if qc == nil {
		return nil, net.ErrClosed
	} else {
		qc := qc.(quic.Connection)
		qs, err := qc.OpenStreamSync(ctx)
		if err != nil {
			if !retry {
				retry = true
				goto retry
			}
			return nil, err
		}
		return &yggdrasilSession{qc, qs}, err
	}
}

func (t *YggdrasilTransport) Accept() (net.Conn, error) {
	return <-t.incoming, nil
}

func (t *YggdrasilTransport) Addr() net.Addr {
	return t.listener.Addr()
}

func (t *YggdrasilTransport) Close() error {
	if err := t.listener.Close(); err != nil {
		return err
	}
	return t.yggdrasil.Close()
}
