package main

import (
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/jwt"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/service"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/config"
	myPostgresRepo "github.com/Miraines/MoonyAndStarry/auth-service/internal/repo/postgres"
	myRedisRepo "github.com/Miraines/MoonyAndStarry/auth-service/internal/repo/redis"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/server"
	myGrpc "github.com/Miraines/MoonyAndStarry/auth-service/internal/transport/grpc"
	"github.com/golang-migrate/migrate/v4"
	migratePostgres "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"log"

	"github.com/go-playground/validator"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config load failed: %v", err)
	}

	zapLogger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("zap logger init failed: %v", err)
	}
	defer zapLogger.Sync()

	db, err := gorm.Open(postgres.Open(cfg.DatabaseURL), &gorm.Config{
		Logger: gormLogger.New(
			zap.NewStdLog(zap.L()),
			gormLogger.Config{LogLevel: gormLogger.Warn},
		),
	})
	if err != nil {
		zapLogger.Fatal("failed to connect to database", zap.Error(err))
	}

	sqlDB, err := db.DB()
	if err != nil {
		zapLogger.Fatal("getting sql.DB failed", zap.Error(err))
	}

	driver, err := migratePostgres.WithInstance(sqlDB, &migratePostgres.Config{})
	if err != nil {
		zapLogger.Fatal("migrate driver init failed", zap.Error(err))
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://scripts/db/migrations",
		"postgres", driver,
	)
	if err != nil {
		zapLogger.Fatal("migrate init failed", zap.Error(err))
	}
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		zapLogger.Fatal("migrate up failed", zap.Error(err))
	}

	redisCli := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddress,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})

	userRepo := myPostgresRepo.NewPostgresUserRepo(db)
	tokenRepo := myRedisRepo.NewRedisTokenRepo(redisCli)
	jwtUtil, _ := jwt.NewJWTUtil(cfg)
	svc := service.NewAuthService(userRepo, tokenRepo, jwtUtil, cfg, validator.New())
	handler := myGrpc.NewHandler(svc, db, redisCli)

	if err := server.StartGRPCServer(cfg, handler, zapLogger); err != nil {
		zapLogger.Fatal("server error", zap.Error(err))
	}
}
