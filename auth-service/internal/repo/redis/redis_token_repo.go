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

func (r *RedisTokenRepo) Revoke(ctx context.Context, jti string, expiresAt time.Time) error {
	err := r.client.Set(ctx, jti, "revoked:"+jti, time.Until(expiresAt)).Err()
	if err != nil {
		return err
	}

	return nil
}

func (r *RedisTokenRepo) IsRevoked(ctx context.Context, jti string) (bool, error) {
	count, err := r.client.Exists(ctx, jti).Result()
	if err != nil {
		return false, err
	}

	return count > 0, nil
}
