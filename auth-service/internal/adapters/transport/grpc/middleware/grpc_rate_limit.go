package middleware

import (
	"context"
	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"net"
	"sync"
	"time"
)

type visitor struct {
	limiter *rate.Limiter
	last    time.Time
}

// NewRateLimitPerIP создаёт gRPC-interceptor с ограничением RPS и LRU-кэшем.
func NewRateLimitPerIP(
	limit, burst int,
	cacheSize int,
	ttl time.Duration,
) grpc.UnaryServerInterceptor {

	visitors, _ := lru.New[string, *visitor](cacheSize)
	var mu sync.Mutex

	// Фоновая очистка неактивных IP.
	go func() {
		ticker := time.NewTicker(ttl)
		for range ticker.C {
			mu.Lock()
			for _, key := range visitors.Keys() {
				if v, ok := visitors.Peek(key); ok && time.Since(v.last) > ttl {
					visitors.Remove(key)
				}
			}
			mu.Unlock()
		}
	}()

	return func(
		ctx context.Context,
		req any,
		_ *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {

		// 1. Извлекаем IP-адрес клиента.
		p, ok := peer.FromContext(ctx)
		if !ok {
			return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded")
		}
		host, _, _ := net.SplitHostPort(p.Addr.String())

		mu.Lock()

		// 2. Берём/создаём visitor для IP.
		v, ok := visitors.Get(host)
		if !ok {
			v = &visitor{
				limiter: rate.NewLimiter(rate.Limit(limit), burst),
			}
			visitors.Add(host, v)
		}
		v.last = time.Now()
		mu.Unlock()

		// 3. Проверяем квоту.
		if !v.limiter.Allow() {
			return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded")
		}
		return handler(ctx, req)
	}
}
