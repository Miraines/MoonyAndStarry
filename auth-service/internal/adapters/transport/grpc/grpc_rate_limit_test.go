package grpc

import (
	"context"
	middleware2 "github.com/Miraines/MoonyAndStarry/auth-service/internal/adapters/transport/grpc/middleware"
	"google.golang.org/grpc/peer"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
)

func ctx(ip string) context.Context {
	return peer.NewContext(
		context.Background(),
		&peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 42}},
	)
}

func TestRateLimitPerIP_BurstAllows(t *testing.T) {
	// limit=1 RPS, burst=2 → два первых вызова «залетят» мгновенно
	intc := middleware2.NewRateLimitPerIP(1, 2, 100, time.Hour)

	hit := func(ctx context.Context) error {
		_, err := intc(ctx, nil, &grpc.UnaryServerInfo{}, func(ctx context.Context, req any) (any, error) {
			return nil, nil
		})
		return err
	}

	ctx := ctx("192.0.2.1")
	if err := hit(ctx); err != nil {
		t.Fatalf("unexpected 1-st call err: %v", err)
	}
	if err := hit(ctx); err != nil {
		t.Fatalf("unexpected 2-nd call err: %v", err)
	}
	// третий подряд уже должен отвалиться
	if err := hit(ctx); err == nil {
		t.Fatal("expected rate-limit error on 3-rd burst call")
	}
}

func TestRateLimitPerIP_SeparateCounters(t *testing.T) {
	intc := middleware2.NewRateLimitPerIP(1, 1, 1000, time.Hour)

	h := func(ctx context.Context) error {
		_, err := intc(ctx, nil, &grpc.UnaryServerInfo{}, func(ctx context.Context, req any) (any, error) {
			return nil, nil
		})
		return err
	}

	// Первый IP
	if err := h(ctx("203.0.113.10")); err != nil {
		t.Fatalf("unexpected err for first host: %v", err)
	}
	if err := h(ctx("203.0.113.10")); err == nil {
		t.Fatal("limit must trigger for first host second hit")
	}

	// Независимый счётчик для другого IP
	if err := h(ctx("198.51.100.5")); err != nil {
		t.Fatalf("second host should not be limited yet, got: %v", err)
	}
}

func TestRateLimitPerIP_TTL_Evicts(t *testing.T) {
	ttl := 15 * time.Millisecond
	intc := middleware2.NewRateLimitPerIP(1, 1, 10, ttl)

	hit := func() error {
		_, err := intc(ctx("10.10.10.10"), nil, &grpc.UnaryServerInfo{}, func(ctx context.Context, req any) (any, error) {
			return nil, nil
		})
		return err
	}

	if err := hit(); err != nil {
		t.Fatalf("first hit should pass: %v", err)
	}
	time.Sleep(ttl + 5*time.Millisecond) // ждём, пока cleaner выкинет visitor
	if err := hit(); err != nil {
		t.Fatalf("after TTL the first token must be renewed, got err: %v", err)
	}
}
