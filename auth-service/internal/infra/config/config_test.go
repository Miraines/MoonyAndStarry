package config

import (
	"testing"
	"time"
)

func TestLoad_Success(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://u:p@localhost/db")
	t.Setenv("JWT_PRIVATE_KEY_PATH", "priv.pem")
	t.Setenv("JWT_PUBLIC_KEY_PATH", "pub.pem")
	t.Setenv("ACCESS_TOKEN_TTL", "2m")
	t.Setenv("REFRESH_TOKEN_TTL", "3h")
	t.Setenv("REDIS_ADDRESS", "localhost:6379")
	t.Setenv("PASSWORD_PEPPER", "pepper")
	t.Setenv("GRPC_ADDRESS", ":50051")
	t.Setenv("TELEGRAM_BOT_TOKEN", "123456:ABC")
	t.Setenv("JWT_ISSUER", "my-svc")
	t.Setenv("JWT_AUDIENCE", "my-aud")
	// необязательные, но пусть будут
	t.Setenv("ALLOWED_ORIGINS", `["https://app.example.com"]`)
	t.Setenv("ALLOW_CREDENTIALS", "true")
	t.Setenv("HTTPS_CERT_FILE", "cert.pem")
	t.Setenv("HTTPS_KEY_FILE", "key.pem")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.AccessTokenTTL != 2*time.Minute {
		t.Fatalf("AccessTokenTTL want 2m, got %v", cfg.AccessTokenTTL)
	}
	if cfg.RefreshTokenTTL != 3*time.Hour {
		t.Fatalf("RefreshTokenTTL want 3h, got %v", cfg.RefreshTokenTTL)
	}
}

func TestLoad_MissingRequired(t *testing.T) {
	// задаём всё, КРОМЕ JWT_ISSUER
	t.Setenv("DATABASE_URL", "db")
	t.Setenv("JWT_PRIVATE_KEY_PATH", "a")
	t.Setenv("JWT_PUBLIC_KEY_PATH", "b")
	t.Setenv("ACCESS_TOKEN_TTL", "1m")
	t.Setenv("REFRESH_TOKEN_TTL", "1h")
	t.Setenv("REDIS_ADDRESS", "r")
	t.Setenv("PASSWORD_PEPPER", "p")
	t.Setenv("GRPC_ADDRESS", "addr")
	t.Setenv("TELEGRAM_BOT_TOKEN", "t")
	t.Setenv("JWT_AUDIENCE", "aud")
	t.Setenv("HTTPS_CERT_FILE", "c")
	t.Setenv("HTTPS_KEY_FILE", "k")

	if _, err := Load(); err == nil {
		t.Fatal("expected error due to missing JWT_ISSUER, got nil")
	}
}
