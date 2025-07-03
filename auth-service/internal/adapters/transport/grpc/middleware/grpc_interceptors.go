package middleware

import (
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_zap "github.com/grpc-ecosystem/go-grpc-middleware/logging/zap"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"go.uber.org/zap"
	"google.golang.org/grpc"
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

func ChainUnaryServer(logger *zap.Logger, limit, burst int) grpc.UnaryServerInterceptor {
	return grpc_middleware.ChainUnaryServer(
		RecoveryInterceptor(),
		LoggingInterceptor(logger),
		MetricsInterceptor(),
		NewRateLimitPerIP(limit, burst, 10_000, time.Hour),
	)
}
