package repo

import (
	"context"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/model"
	"github.com/google/uuid"
)

type UserRepo interface {
	CreateUser(ctx context.Context, u model.User) (uuid.UUID, error)

	GetUserByEmail(ctx context.Context, email string) (model.User, error)

	GetUserByID(ctx context.Context, id uuid.UUID) (model.User, error)

	UpdateUser(ctx context.Context, u model.User) error

	DeleteUser(ctx context.Context, id uuid.UUID) error

	GetUserByUsername(ctx context.Context, username string) (model.User, error)

	GetUserByTelegramID(ctx context.Context, id int64) (model.User, error)
}
