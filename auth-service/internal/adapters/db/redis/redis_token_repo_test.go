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
	t.Cleanup(mr.Close)

	client := redisv9.NewClient(&redisv9.Options{
		Addr: mr.Addr(),
	})
	return NewRedisTokenRepo(client)
}

func TestRedisTokenRepo_StoreAndIsRevoked(t *testing.T) {
	repo := newRepo(t)
	ctx := context.Background()

	exp := time.Now().Add(10 * time.Minute)
	if err := repo.Store(ctx, "jti1", exp); err != nil {
		t.Fatalf("Store: %v", err)
	}

	revoked, err := repo.IsRevoked(ctx, "jti1")
	if err != nil {
		t.Fatalf("IsRevoked err: %v", err)
	}
	if revoked {
		t.Fatal("token should NOT be revoked right after Store")
	}
}

func TestRedisTokenRepo_RevokeAndIsRevoked(t *testing.T) {
	repo := newRepo(t)
	ctx := context.Background()

	exp := time.Now().Add(1 * time.Minute)
	if err := repo.Revoke(ctx, "jti2", exp); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	revoked, err := repo.IsRevoked(ctx, "jti2")
	if err != nil {
		t.Fatalf("IsRevoked err: %v", err)
	}
	if !revoked {
		t.Fatal("token should be marked revoked")
	}
}

func TestRedisTokenRepo_RevokeAccessAndIsAccessRevoked(t *testing.T) {
	repo := newRepo(t)
	ctx := context.Background()

	exp := time.Now().Add(30 * time.Second)
	if err := repo.RevokeAccess(ctx, "access-jti", exp); err != nil {
		t.Fatalf("RevokeAccess: %v", err)
	}

	revoked, err := repo.IsAccessRevoked(ctx, "access-jti")
	if err != nil {
		t.Fatalf("IsAccessRevoked err: %v", err)
	}
	if !revoked {
		t.Fatal("access-token should be marked revoked")
	}
}

func TestRedisTokenRepo_IsRevoked_KeyAbsent(t *testing.T) {
	repo := newRepo(t)
	ctx := context.Background()

	revoked, err := repo.IsRevoked(ctx, "absent-jti")
	if err != nil {
		t.Fatalf("IsRevoked err: %v", err)
	}
	if revoked {
		t.Fatal("absent key must be considered NOT revoked")
	}
}
