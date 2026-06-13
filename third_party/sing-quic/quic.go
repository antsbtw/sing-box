package qtls

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	M "github.com/sagernet/sing/common/metadata"
	aTLS "github.com/sagernet/sing/common/tls"
)

type QUICOptions struct {
	IdleTimeout             time.Duration
	KeepAlivePeriod         time.Duration
	StreamReceiveWindow     uint64
	ConnectionReceiveWindow uint64
	MaxConcurrentStreams    int
	InitialPacketSize       int
	DisablePathMTUDiscovery bool
}

type Config interface {
	Dial(ctx context.Context, conn net.PacketConn, addr net.Addr, config *quic.Config) (*quic.Conn, error)
	DialEarly(ctx context.Context, conn net.PacketConn, addr net.Addr, config *quic.Config) (*quic.Conn, error)
	CreateTransport(conn net.PacketConn, quicConnPtr **quic.Conn, serverAddr M.Socksaddr, quicConfig *quic.Config) http.RoundTripper
}

type ServerConfig interface {
	Listen(conn net.PacketConn, config *quic.Config) (Listener, error)
	ListenEarly(conn net.PacketConn, config *quic.Config) (EarlyListener, error)
	ConfigureHTTP3()
}

type Listener interface {
	Accept(ctx context.Context) (*quic.Conn, error)
	Close() error
	Addr() net.Addr
}

type EarlyListener interface {
	Accept(ctx context.Context) (*quic.Conn, error)
	Close() error
	Addr() net.Addr
}

func ApplyQUICOptions(quicConfig *quic.Config, options QUICOptions) {
	if options.StreamReceiveWindow != 0 {
		quicConfig.InitialStreamReceiveWindow = options.StreamReceiveWindow
		quicConfig.MaxStreamReceiveWindow = options.StreamReceiveWindow
	}
	if options.ConnectionReceiveWindow != 0 {
		quicConfig.InitialConnectionReceiveWindow = options.ConnectionReceiveWindow
		quicConfig.MaxConnectionReceiveWindow = options.ConnectionReceiveWindow
	}
	if options.MaxConcurrentStreams > 0 {
		quicConfig.MaxIncomingStreams = int64(options.MaxConcurrentStreams)
	}
	if options.KeepAlivePeriod > 0 {
		quicConfig.KeepAlivePeriod = options.KeepAlivePeriod
	}
	if options.IdleTimeout > 0 {
		quicConfig.MaxIdleTimeout = options.IdleTimeout
	}
	if options.InitialPacketSize > 0 {
		quicConfig.InitialPacketSize = uint16(options.InitialPacketSize)
	}
	if options.DisablePathMTUDiscovery {
		quicConfig.DisablePathMTUDiscovery = true
	}
}

func quicConfigWithHandshakeTimeout(quicConfig *quic.Config, handshakeTimeout time.Duration) *quic.Config {
	if handshakeTimeout <= 0 {
		return quicConfig
	}
	if quicConfig == nil {
		return &quic.Config{HandshakeIdleTimeout: handshakeTimeout}
	}
	if quicConfig.HandshakeIdleTimeout != 0 {
		return quicConfig
	}
	quicConfig.HandshakeIdleTimeout = handshakeTimeout
	return quicConfig
}

func Dial(ctx context.Context, conn net.PacketConn, addr net.Addr, config aTLS.Config, quicConfig *quic.Config) (*quic.Conn, error) {
	quicConfig = quicConfigWithHandshakeTimeout(quicConfig, config.HandshakeTimeout())
	if quicTLSConfig, isQUICConfig := config.(Config); isQUICConfig {
		quicConn, err := quicTLSConfig.Dial(ctx, conn, addr, quicConfig)
		return quicConn, WrapError(err)
	}
	tlsConfig, err := config.STDConfig()
	if err != nil {
		return nil, err
	}
	quicConn, err := quic.Dial(ctx, conn, addr, tlsConfig, quicConfig)
	return quicConn, WrapError(err)
}

func DialEarly(ctx context.Context, conn net.PacketConn, addr net.Addr, config aTLS.Config, quicConfig *quic.Config) (*quic.Conn, error) {
	quicConfig = quicConfigWithHandshakeTimeout(quicConfig, config.HandshakeTimeout())
	if quicTLSConfig, isQUICConfig := config.(Config); isQUICConfig {
		quicConn, err := quicTLSConfig.DialEarly(ctx, conn, addr, quicConfig)
		return quicConn, WrapError(err)
	}
	tlsConfig, err := config.STDConfig()
	if err != nil {
		return nil, err
	}
	quicConn, err := quic.DialEarly(ctx, conn, addr, tlsConfig, quicConfig)
	return quicConn, WrapError(err)
}

func CreateTransport(conn net.PacketConn, quicConnPtr **quic.Conn, serverAddr M.Socksaddr, config aTLS.Config, quicConfig *quic.Config) (http.RoundTripper, error) {
	handshakeTimeout := config.HandshakeTimeout()
	quicConfig = quicConfigWithHandshakeTimeout(quicConfig, handshakeTimeout)
	if quicTLSConfig, isQUICConfig := config.(Config); isQUICConfig {
		return quicTLSConfig.CreateTransport(conn, quicConnPtr, serverAddr, quicConfig), nil
	}
	tlsConfig, err := config.STDConfig()
	if err != nil {
		return nil, err
	}
	return &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig:      quicConfig,
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			cfg = quicConfigWithHandshakeTimeout(cfg, handshakeTimeout)
			quicConn, err := quic.DialEarly(ctx, conn, serverAddr.UDPAddr(), tlsCfg, cfg)
			if err != nil {
				return nil, WrapError(err)
			}
			*quicConnPtr = quicConn
			return quicConn, nil
		},
	}, nil
}

func Listen(conn net.PacketConn, config aTLS.ServerConfig, quicConfig *quic.Config) (Listener, error) {
	quicConfig = quicConfigWithHandshakeTimeout(quicConfig, config.HandshakeTimeout())
	if quicTLSConfig, isQUICConfig := config.(ServerConfig); isQUICConfig {
		listener, err := quicTLSConfig.Listen(conn, quicConfig)
		return listener, WrapError(err)
	}
	tlsConfig, err := config.STDConfig()
	if err != nil {
		return nil, err
	}
	listener, err := quic.Listen(conn, tlsConfig, quicConfig)
	return listener, WrapError(err)
}

func ListenEarly(conn net.PacketConn, config aTLS.ServerConfig, quicConfig *quic.Config) (EarlyListener, error) {
	quicConfig = quicConfigWithHandshakeTimeout(quicConfig, config.HandshakeTimeout())
	if quicTLSConfig, isQUICConfig := config.(ServerConfig); isQUICConfig {
		listener, err := quicTLSConfig.ListenEarly(conn, quicConfig)
		return listener, WrapError(err)
	}
	tlsConfig, err := config.STDConfig()
	if err != nil {
		return nil, err
	}
	listener, err := quic.ListenEarly(conn, tlsConfig, quicConfig)
	return listener, WrapError(err)
}

func ConfigureHTTP3(config aTLS.ServerConfig) error {
	if len(config.NextProtos()) == 0 {
		config.SetNextProtos([]string{http3.NextProtoH3})
	}
	if quicTLSConfig, isQUICConfig := config.(ServerConfig); isQUICConfig {
		quicTLSConfig.ConfigureHTTP3()
		return nil
	}
	tlsConfig, err := config.STDConfig()
	if err != nil {
		return err
	}
	http3.ConfigureTLSConfig(tlsConfig)
	return nil
}
