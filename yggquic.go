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
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/neilalexander/generique/sync"

	iwt "github.com/Arceliar/ironwood/types"
	"github.com/quic-go/quic-go"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
)

type YggdrasilTransport struct {
	ctx         context.Context
	cancel      context.CancelFunc
	yggdrasil   net.PacketConn
	listener    *quic.Listener
	transport   *quic.Transport
	tlsConfig   *tls.Config
	quicConfig  *quic.Config
	incoming    chan *yggdrasilStream
	connections sync.Map[string, *yggdrasilConnection]
	dials       sync.Map[string, *yggdrasilDial]
}

type yggdrasilConnection struct {
	context.Context
	context.CancelFunc
	*quic.Conn
}

type yggdrasilStream struct {
	*yggdrasilConnection
	*quic.Stream
}

type yggdrasilDial struct {
	context.Context
	context.CancelFunc
}

func New(ygg *core.Core, qc *quic.Config) (*YggdrasilTransport, error) {
	if qc == nil {
		qc = &quic.Config{
			HandshakeIdleTimeout:    time.Second * 5,
			MaxIdleTimeout:          time.Second * 60,
			InitialPacketSize:       uint16(ygg.MTU()),
			DisablePathMTUDiscovery: true,
		}
	}

	privateKey := ygg.PrivateKey()
	publicKey := ygg.PublicKey()

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName: hex.EncodeToString(publicKey),
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	certbytes, err := x509.CreateCertificate(rand.Reader, cert, cert, publicKey, privateKey)
	if err != nil {
		return nil, err
	}

	tr := &YggdrasilTransport{
		tlsConfig: &tls.Config{
			ServerName:         hex.EncodeToString(publicKey),
			ClientAuth:         tls.RequireAnyClientCert,
			InsecureSkipVerify: true,
			Certificates: []tls.Certificate{{
				Certificate: [][]byte{certbytes},
				PrivateKey:  privateKey,
			}},
		},
		quicConfig: qc,
		transport: &quic.Transport{
			Conn: ygg,
		},
		yggdrasil: ygg,
		incoming:  make(chan *yggdrasilStream),
	}
	tr.ctx, tr.cancel = context.WithCancel(context.Background())

	if tr.listener, err = tr.transport.Listen(tr.tlsConfig, tr.quicConfig); err != nil {
		return nil, fmt.Errorf("quic.Listen: %w", err)
	}

	go tr.connectionAcceptLoop(tr.ctx)
	return tr, nil
}

func (t *YggdrasilTransport) connectionAcceptLoop(ctx context.Context) {
	for {
		qc, err := t.listener.Accept(ctx)
		if err != nil {
			return
		}

		qstate := qc.ConnectionState()
		if !verifyPeer(qc.RemoteAddr(), qstate.TLS.PeerCertificates) {
			qc.CloseWithError(0, "Peer verification failed")
			continue
		}

		ctx, cancel := context.WithCancel(t.ctx)
		yc := &yggdrasilConnection{ctx, cancel, qc}

		// If there's already an open connection for this node then we
		// will want to shut down the existing one and replace it with
		// this one.
		host := qc.RemoteAddr().String()
		if eqc, ok := t.connections.Swap(host, yc); ok {
			eqc.CancelFunc()
		}

		go t.streamAcceptLoop(yc)

		// Now if there are any in-progress dials, we can cancel those
		// too as we now have an open connection that we can open new
		// streams on.
		if dial, ok := t.dials.LoadAndDelete(host); ok {
			dial.CancelFunc()
		}
	}
}

func (t *YggdrasilTransport) streamAcceptLoop(yc *yggdrasilConnection) {
	host := yc.RemoteAddr().String()
	defer yc.CloseWithError(0, "Timed out") // nolint:errcheck
	defer t.connections.Delete(host)

	for {
		qs, err := yc.AcceptStream(yc.Context)
		if err != nil {
			return
		}
		select {
		case t.incoming <- &yggdrasilStream{yc, qs}:
			// An Accept call is waiting.
		case <-yc.Context.Done():
			// We've timed out waiting for a call to Accept
			// to handle the connection.
			return
		}
	}
}

func (t *YggdrasilTransport) Dial(network, host string) (net.Conn, error) {
	return t.DialContext(context.TODO(), network, host)
}

func (t *YggdrasilTransport) DialContext(ctx context.Context, network, host string) (net.Conn, error) {
	if network != "yggdrasil" {
		return nil, fmt.Errorf("network must be 'yggdrasil'")
	}

	// Check if there is already a dial to this host in progress.
	// If there is then we will wait for it.
	if dial, ok := t.dials.Load(host); ok {
		<-dial.Done()
	}

	// We might want to retrying once if part of the dial process fails,
	// but keep a track of whether we're already retrying.
	var retrying bool
retry:
	yc, ok := t.connections.Load(host)
	if !ok {
		// Even after a dial, there's no connection. This means we
		// probably failed to dial, so let's try it again.
		if yc, ok = t.connections.Load(host); !ok {
			// A cancellable context means we can cancel the dial in
			// progress from elsewhere if we need to.
			dialctx, dialcancel := context.WithTimeout(ctx, time.Second*5)
			t.dials.Store(host, &yggdrasilDial{dialctx, dialcancel})
			defer dialcancel()
			defer t.dials.Delete(host)

			// Decode the address from hex.
			addr := make(iwt.Addr, ed25519.PublicKeySize)
			k, err := hex.DecodeString(host)
			if err != nil {
				return nil, err
			}
			copy(addr, k)

			// Attempt to open a QUIC session.
			var qc *quic.Conn
			if qc, err = t.transport.Dial(dialctx, addr, t.tlsConfig, t.quicConfig); err != nil {
				return nil, err
			}

			// Check the peer's identity against their source address.
			qstate := qc.ConnectionState()
			if !verifyPeer(addr, qstate.TLS.PeerCertificates) {
				qc.CloseWithError(0, "Peer verification failed")
				return nil, fmt.Errorf("peer verification failed")
			}

			// If we succeeded then we'll store our QUIC connection so
			// that the next dial can open a stream on it directly. Start
			// the accept loop so that streams can be accepted.
			{
				ctx, cancel := context.WithCancel(context.Background())
				yc = &yggdrasilConnection{ctx, cancel, qc}
				t.connections.Store(host, yc)
				go t.streamAcceptLoop(yc)
			}
		}
	}
	// We've either found a session or we successfully
	// dialed a new one, so open a stream on it.
	qs, err := yc.OpenStreamSync(ctx)
	if err != nil {
		// We failed to open a stream, so if this isn't a
		// retry, then let's try opening a new connection.
		if !retrying {
			retrying = true
			goto retry
		}
		return nil, err
	}
	return &yggdrasilStream{yc, qs}, err
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

func verifyPeer(remote net.Addr, cert []*x509.Certificate) bool {
	if len(cert) != 1 {
		return false
	}
	remotestr := remote.String()
	switch cert[0].PublicKeyAlgorithm {
	case x509.Ed25519:
		return hex.EncodeToString(cert[0].PublicKey.(ed25519.PublicKey)) == remotestr
	default:
		return false
	}
}
