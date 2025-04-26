package service

import (
	"context"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/dto"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/jwt"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/model"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/config"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/repo"
	validate "github.com/go-playground/validator/v10"
)

type AuthService interface {
	Register(ctx context.Context, dto dto.RegisterDTO) (model.TokenPair, error)
	Login(ctx context.Context, dto dto.LoginDTO) (model.TokenPair, error)
	Validate(ctx context.Context, dto dto.ValidateDTO) (model.User, error)
	Refresh(ctx context.Context, dto dto.RefreshDTO) (model.TokenPair, error)
	Logout(ctx context.Context, dto dto.LogoutDTO) error
}

func NewAuthService(userRepo repo.UserRepo, tokenRepo repo.TokenRepo, jwtUtil jwt.JWTUtil, cfg *config.Config, v *validate.Validate) AuthService {
	return &authService{
		userRepo:  userRepo,
		tokenRepo: tokenRepo,
		jwtUtil:   jwtUtil,
		cfg:       cfg,
		v:         v,
	}
}
