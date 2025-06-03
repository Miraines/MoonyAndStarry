package middleware

import (
	"context"
	"net"
	"testing"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
)

func TestRateLimitPerIP(t *testing.T) {
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.IPAddr{IP: net.ParseIP("127.0.0.1")}})
	handlerCalled := 0
	i := RateLimitPerIP(1, 1)
	handler := func(ctx context.Context, req interface{}) (interface{}, error) { handlerCalled++; return nil, nil }
	if _, err := i(ctx, nil, &grpc.UnaryServerInfo{}, handler); err != nil {
		t.Fatal(err)
	}
	if _, err := i(ctx, nil, &grpc.UnaryServerInfo{}, handler); err == nil {
		t.Fatal("expected rate limit")
	}
	if handlerCalled != 1 {
		t.Fatalf("handler %d", handlerCalled)
	}
}

func TestChain(t *testing.T) {
	logger := zap.NewNop()
	c := ChainUnaryServer(logger, 1, 1)
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.IPAddr{IP: net.ParseIP("127.0.0.1")}})
	_, err := c(ctx, nil, &grpc.UnaryServerInfo{}, func(ctx context.Context, req interface{}) (interface{}, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
}
