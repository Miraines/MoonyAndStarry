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
	val, err := r.client.Get(ctx, jti).Result()
	switch {
	case err == redis.Nil:
		return false, nil //ключа нет —  НЕ отозван
	case err != nil:
		return true, err //считаем отозванным, плюс ошибка вверх
	default:
		return val == "1", nil // "1" – отозван
	}
}

func (r *RedisTokenRepo) RevokeAccess(ctx context.Context, jti string, exp time.Time) error {
	return r.client.Set(ctx, "a:"+jti, 1, time.Until(exp)).Err()
}

func (r *RedisTokenRepo) IsAccessRevoked(ctx context.Context, jti string) (bool, error) {
	n, err := r.client.Exists(ctx, "a:"+jti).Result()
	return n > 0, err
}

func (r *RedisTokenRepo) Store(ctx context.Context, jti string, exp time.Time) error {
	return r.client.Set(ctx, jti, "0", safeTTL(exp)).Err() // явно пишем "0"
}

func safeTTL(exp time.Time) time.Duration {
	ttl := time.Until(exp)
	if ttl <= 0 {
		// задаём минимальный TTL, чтобы ключ всё-таки исчез
		return time.Hour
	}
	return ttl
}
