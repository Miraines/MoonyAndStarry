package postgres

import (
	"context"
	"errors"
	customErrors "github.com/Miraines/MoonyAndStarry/auth-service/internal/domain/auth/errors"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/domain/auth/model"
	"github.com/google/uuid"
	"github.com/jackc/pgconn"
	"gorm.io/gorm"
)

type PostgresUserRepo struct {
	db *gorm.DB
}

func NewPostgresUserRepo(db *gorm.DB) *PostgresUserRepo {
	return &PostgresUserRepo{db: db}
}

func (p *PostgresUserRepo) CreateUser(ctx context.Context, user model.User) (uuid.UUID, error) {
	res := p.db.WithContext(ctx).Create(&user)
	if err := res.Error; err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return uuid.Nil, customErrors.ErrAlreadyExists
		}
		return uuid.Nil, customErrors.WrapInternal(err, "CreateUser")
	}
	return user.ID, nil
}

func (p *PostgresUserRepo) GetUserByEmail(ctx context.Context, email string) (model.User, error) {
	var u model.User
	res := p.db.WithContext(ctx).Where("email = ?", email).First(&u)
	if errors.Is(res.Error, gorm.ErrRecordNotFound) {
		return model.User{}, customErrors.ErrNotFound
	}
	if err := res.Error; err != nil {
		return model.User{}, customErrors.WrapInternal(err, "GetUserByEmail")
	}

	return u, nil
}

func (p *PostgresUserRepo) GetUserByID(ctx context.Context, id uuid.UUID) (model.User, error) {
	var u model.User
	res := p.db.WithContext(ctx).Where("id = ?", id).First(&u)
	if errors.Is(res.Error, gorm.ErrRecordNotFound) {
		return model.User{}, customErrors.ErrNotFound
	}
	if err := res.Error; err != nil {
		return model.User{}, customErrors.WrapInternal(err, "GetUserByID")
	}

	return u, nil
}

func (p *PostgresUserRepo) GetUserByUsername(ctx context.Context, username string) (model.User, error) {
	var u model.User
	res := p.db.WithContext(ctx).Where("username = ?", username).First(&u)
	if errors.Is(res.Error, gorm.ErrRecordNotFound) {
		return model.User{}, customErrors.ErrNotFound
	}
	if err := res.Error; err != nil {
		return model.User{}, customErrors.WrapInternal(err, "GetUserByUsername")
	}

	return u, nil
}

func (p *PostgresUserRepo) GetUserByTelegramID(ctx context.Context, id int64) (model.User, error) {
	var u model.User
	res := p.db.WithContext(ctx).Where("telegram_id = ?", id).First(&u)
	if errors.Is(res.Error, gorm.ErrRecordNotFound) {
		return model.User{}, customErrors.ErrNotFound
	}
	if err := res.Error; err != nil {
		return model.User{}, customErrors.WrapInternal(err, "GetUserByTelegramID")
	}

	return u, nil
}

func (p *PostgresUserRepo) UpdateUser(ctx context.Context, user model.User) error {
	res := p.db.WithContext(ctx).Save(&user)
	if err := res.Error; err != nil {
		return customErrors.WrapInternal(err, "UpdateUser")
	}
	if res.Error == nil && res.RowsAffected == 0 {
		return nil
	}

	return nil
}

func (p *PostgresUserRepo) DeleteUser(ctx context.Context, id uuid.UUID) error {
	res := p.db.WithContext(ctx).Delete(&model.User{}, id)
	if err := res.Error; err != nil {
		return customErrors.WrapInternal(err, "DeleteUser")
	}
	if res.RowsAffected == 0 {
		return customErrors.ErrNotFound
	}

	return nil
}
