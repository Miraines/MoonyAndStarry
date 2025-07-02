package middleware

import (
	"context"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_zap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"net"
	"sync"
	"time"
)

func RecoveryInterceptor() grpc.UnaryServerInterceptor {
	return grpc_recovery.UnaryServerInterceptor()
}

func LoggingInterceptor(logger *zap.Logger) grpc.UnaryServerInterceptor {
	return grpc_zap.UnaryServerInterceptor(logger)
}

func MetricsInterceptor() grpc.UnaryServerInterceptor {
	return grpc_prometheus.UnaryServerInterceptor
}

func RateLimitPerIP(limit, burst int) grpc.UnaryServerInterceptor {
	limiters := sync.Map{} // key = string(IP), value = *rate.Limiter

	return func(ctx context.Context, req interface{},
		info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {

		// 1. Достаём IP из контекста
		p, ok := peer.FromContext(ctx)
		if !ok {
			// нет данных о клиенте — считаем злоупотреблением
			return nil, status.Errorf(codes.ResourceExhausted, "rate limit exceeded")
		}
		host, _, err := net.SplitHostPort(p.Addr.String())
		if err != nil {
			host = p.Addr.String() // fallback
		}

		// 2. Берём/создаём лимитер для этого IP
		lIface, _ := limiters.LoadOrStore(host,
			rate.NewLimiter(rate.Limit(limit), burst))
		l := lIface.(*rate.Limiter)

		// 3. Проверяем квоту
		if !l.Allow() {
			return nil, status.Errorf(codes.ResourceExhausted, "rate limit exceeded")
		}
		return handler(ctx, req)
	}
}

func ChainUnaryServer(logger *zap.Logger, limit, burst int) grpc.UnaryServerInterceptor {
	return grpc_middleware.ChainUnaryServer(
		RecoveryInterceptor(),
		LoggingInterceptor(logger),
		MetricsInterceptor(),
		NewRateLimitPerIP(limit, burst, 10_000, time.Hour),
	)
}
