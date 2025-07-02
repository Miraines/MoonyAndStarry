package server

import (
	"context"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Miraines/MoonyAndStarry/auth-service/internal/config"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/transport/grpc/middleware"
	authv1 "github.com/Miraines/MoonyAndStarry/auth-service/pkg/proto/v1"

	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

// StartGRPCServer поднимает gRPC-сервер с middleware и graceful shutdown
func StartGRPCServer(cfg *config.Config, handler authv1.AuthServer, logger *zap.Logger) error {
	// 1. Открыть порт
	lis, err := net.Listen("tcp", cfg.GRPCAddress)
	if err != nil {
		return err
	}

	// 3. Составить цепочку Unary‐interceptor‐ов из вашего middleware-пакета
	unaryInterceptor := middleware.ChainUnaryServer(logger, 10, 100)

	creds, err := credentials.NewServerTLSFromFile(cfg.HTTPSCertFile, cfg.HTTPSKeyFile)
	if err != nil {
		return err
	}

	// 4. Создать сам gRPC‐сервер
	grpcServer := grpc.NewServer(
		grpc.Creds(creds),
		grpc.UnaryInterceptor(unaryInterceptor),
	)

	// 5. Зарегистрировать сервис и метрики
	authv1.RegisterAuthServer(grpcServer, handler)
	grpc_prometheus.Register(grpcServer)
	grpc_prometheus.EnableHandlingTimeHistogram()
	reflection.Register(grpcServer)

	// 6. Запустить в горутине
	go func() {
		logger.Info("gRPC server listening", zap.String("addr", cfg.GRPCAddress))
		if err := grpcServer.Serve(lis); err != nil {
			logger.Fatal("failed to serve gRPC", zap.Error(err))
		}
	}()

	// 7. Ждём сигнала на остановку
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("shutdown signal received, stopping gRPC server…")

	// 8. Graceful stop с 5-секундным таймаутом
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
