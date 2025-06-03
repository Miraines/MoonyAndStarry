package config

import (
	"os"
	"testing"
	"time"
)

func TestLoadFromEnv(t *testing.T) {
	os.Setenv("DATABASE_URL", "db")
	os.Setenv("JWT_PRIVATE_KEY_PATH", "a")
	os.Setenv("JWT_PUBLIC_KEY_PATH", "b")
	os.Setenv("ACCESS_TOKEN_TTL", "1m")
	os.Setenv("REFRESH_TOKEN_TTL", "1h")
	os.Setenv("REDIS_ADDRESS", "r")
	os.Setenv("PASSWORD_PEPPER", "p")
	os.Setenv("GRPC_ADDRESS", "addr")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AccessTokenTTL != time.Minute {
		t.Fatalf("ttl: %v", cfg.AccessTokenTTL)
	}
}
