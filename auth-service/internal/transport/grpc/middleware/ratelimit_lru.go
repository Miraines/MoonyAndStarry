package middleware

import (
	"context"
	lru "github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"net"
	"time"
)

// NewRateLimitPerIP создаёт middleware с LRU-кэшем, где каждая запись
// живёт entryTTL и автоматически удаляется (нет утечек памяти).
func NewRateLimitPerIP(
	limit, burst int, // tokens/sec и размер бакета
	cacheSize int, // макс. IP в памяти
	entryTTL time.Duration, // TTL одной записи
) grpc.UnaryServerInterceptor {

	// ❶ LRU кэш: только одно возвращаемое значение
	visitors := lru.NewLRU[string, *rate.Limiter](cacheSize, nil, entryTTL)

	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {

		// ❷ Определяем IP клиента
		p, ok := peer.FromContext(ctx)
		if !ok {
			return nil, status.Errorf(codes.ResourceExhausted, "rate limit exceeded")
		}
		host, _, err := net.SplitHostPort(p.Addr.String())
		if err != nil {
			host = p.Addr.String() // fallback
		}

		// ❸ Берём лимитер из кэша либо создаём новый
		lim, found := visitors.Get(host)
		if !found {
			lim = rate.NewLimiter(rate.Limit(limit), burst)
			visitors.Add(host, lim)
		}

		// ❹ Проверяем квоту
		if !lim.Allow() {
			return nil, status.Errorf(codes.ResourceExhausted, "rate limit exceeded")
		}
		return handler(ctx, req)
	}
}
