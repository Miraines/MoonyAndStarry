package middleware

import (
	"context"
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
)

// маленький helper
func ctxIP(ip string) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 80},
	})
}

func TestChainUnaryServer_PanicRecovered(t *testing.T) {
	logger := zap.NewExample()
	chain := ChainUnaryServer(logger, 10, 10) // высокая квота, чтобы не мешала

	_, err := chain(ctxIP("8.8.8.8"), nil, &grpc.UnaryServerInfo{},
		func(ctx context.Context, req any) (any, error) {
			panic("boom") // должно перехватиться recovery-interceptor’ом
		})
	if err == nil {
		t.Fatal("panic should be converted to error by recovery interceptor")
	}
}

func TestChainUnaryServer_RateLimitInsideChain(t *testing.T) {
	logger := zap.NewNop()
	chain := ChainUnaryServer(logger, 1, 1)

	h := func(ctx context.Context) error {
		_, err := chain(ctx, nil, &grpc.UnaryServerInfo{},
			func(ctx context.Context, req any) (any, error) { return nil, nil })
		return err
	}

	ctx := ctxIP("9.9.9.9")
	if err := h(ctx); err != nil {
		t.Fatalf("first call unexpected err: %v", err)
	}
	if err := h(ctx); err == nil {
		t.Fatal("second call must hit rate-limit inside chain")
	}
	// Подождём секунду, чтобы токен восстановился
	time.Sleep(1 * time.Second)
	if err := h(ctx); err != nil {
		t.Fatalf("after cool-down call still limited: %v", err)
	}
}
