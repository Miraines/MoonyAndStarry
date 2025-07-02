package repo

import (
	"context"
	"time"
)

type TokenRepo interface {
	RevokeAccess(ctx context.Context, jti string, expiresAt time.Time) error

	IsAccessRevoked(ctx context.Context, jti string) (bool, error)

	Revoke(ctx context.Context, jti string, expiresAt time.Time) error

	IsRevoked(ctx context.Context, jti string) (bool, error)
}
