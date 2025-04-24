package repo

import (
	"context"
	"time"
)

type TokenRepo interface {
	Revoke(ctx context.Context, jti string, expiresAt time.Time) error

	IsRevoked(ctx context.Context, jti string) (bool, error)
}
