package redis

import (
	"context"
	"github.com/redis/go-redis/v9"
	"time"
)

type RedisTokenRepo struct {
	client *redis.Client
}

func NewRedisTokenRepo(client *redis.Client) *RedisTokenRepo {
	return &RedisTokenRepo{
		client: client,
	}
}

func (r *RedisTokenRepo) Revoke(ctx context.Context, jti string, exp time.Time) error {
	return r.client.Set(ctx, jti, 1, time.Until(exp)).Err()
}

func (r *RedisTokenRepo) IsRevoked(ctx context.Context, jti string) (bool, error) {
	n, err := r.client.Exists(ctx, jti).Result()
	return n > 0, err
}

func (r *RedisTokenRepo) RevokeAccess(ctx context.Context, jti string, exp time.Time) error {
	return r.client.Set(ctx, "a:"+jti, 1, time.Until(exp)).Err()
}

func (r *RedisTokenRepo) IsAccessRevoked(ctx context.Context, jti string) (bool, error) {
	n, err := r.client.Exists(ctx, "a:"+jti).Result()
	return n > 0, err
}
