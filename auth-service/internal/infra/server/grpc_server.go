package server

import (
	"context"
	"github.com/Miraines/MoonyAndStarry/auth-service/api/proto/v1"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/adapters/transport/grpc/middleware"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/infra/config"
	"github.com/pkg/errors"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
	"net"
	"time"

	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

// StartGRPCServer поднимает gRPC-сервер с middleware и graceful shutdown
func StartGRPCServer(ctx context.Context, cfg *config.Config, handler authv1.AuthServer, logger *zap.Logger) error {
	// 1. Открыть порт
	lis, err := net.Listen("tcp", cfg.GRPCAddress)
	if err != nil {
		return err
	}

	// 2. Составить цепочку Unary‐interceptor‐ов из вашего middleware-пакета
	unaryInterceptor := middleware.ChainUnaryServer(logger, 10, 100)

	creds, err := credentials.NewServerTLSFromFile(cfg.HTTPSCertFile, cfg.HTTPSKeyFile)
	if err != nil {
		return err
	}

	// 3. Создать сам gRPC‐сервер
	grpcServer := grpc.NewServer(
		grpc.Creds(creds),
		grpc.UnaryInterceptor(unaryInterceptor),
	)

	// 4. Зарегистрировать сервис и метрики
	authv1.RegisterAuthServer(grpcServer, handler)
	grpc_prometheus.Register(grpcServer)
	grpc_prometheus.EnableHandlingTimeHistogram()
	reflection.Register(grpcServer)

	// 5. Запустить в горутине
	go func() {
		logger.Info("gRPC server listening", zap.String("addr", cfg.GRPCAddress))
		if err := grpcServer.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			logger.Fatal("failed to serve gRPC", zap.Error(err))
		}
	}()

	// 6. Ждём сигнала на остановку
	<-ctx.Done()
	logger.Info("ctx cancelled, stopping gRPC server…")

	// 7. Graceful stop с 5-секундным таймаутом
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(done)
	}()

	select {
	case <-ctx.Done():
		grpcServer.Stop()
	case <-done:
	}
	logger.Info("gRPC server stopped")
	return nil
}
