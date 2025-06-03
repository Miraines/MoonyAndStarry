package redis

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	redisv9 "github.com/redis/go-redis/v9"
)

func newRepo(t *testing.T) *RedisTokenRepo {
	mr := miniredis.RunT(t)
	client := redisv9.NewClient(&redisv9.Options{Addr: mr.Addr()})
	return NewRedisTokenRepo(client)
}

func TestRedisTokenRepo_Revoke(t *testing.T) {
	repo := newRepo(t)
	ctx := context.Background()
	exp := time.Now().Add(time.Minute)
	if err := repo.Revoke(ctx, "jti", exp); err != nil {
		t.Fatalf("revoke %v", err)
	}
	ok, err := repo.IsRevoked(ctx, "jti")
	if err != nil || !ok {
		t.Fatalf("is revoked %v %v", ok, err)
	}
}
