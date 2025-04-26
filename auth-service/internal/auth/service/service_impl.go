package service

import (
	"context"
	"errors"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/dto"
	customErrors "github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/errors"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/jwt"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/model"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/config"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/repo"
	"github.com/alexedwards/argon2id"
	"github.com/go-playground/validator"
	"github.com/google/uuid"
	"time"
)

type authService struct {
	userRepo  repo.UserRepo
	tokenRepo repo.TokenRepo
	jwtUtil   jwt.JWTUtil
	cfg       *config.Config
	v         *validator.Validate
}

func (a *authService) Register(ctx context.Context, dto dto.RegisterDTO) (model.TokenPair, error) {

	if err := a.v.Struct(dto); err != nil {
		return model.TokenPair{}, customErrors.NewInvalidArgument(err.Error())
	}

	passwordHash, err := argon2id.CreateHash(dto.Password+a.cfg.PasswordPepper, argon2id.DefaultParams)

	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "Register")
	}

	user := model.User{
		Username:     dto.Username,
		ID:           uuid.New(),
		Email:        dto.Email,
		PasswordHash: passwordHash,
	}
	res, err := a.userRepo.CreateUser(ctx, user)

	if err != nil {
		if errors.Is(err, customErrors.ErrAlreadyExists) {
			return model.TokenPair{}, customErrors.ErrAlreadyExists
		}

		return model.TokenPair{}, customErrors.WrapInternal(err, "Register")
	}

	accessToken, atExp, _, err := a.jwtUtil.GenerateAccessToken(res, []string{"user"})
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "Register")
	}
	refreshToken, rtExp, _, err := a.jwtUtil.GenerateRefreshToken(res)
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "Register")
	}
	now := time.Now()

	return model.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		AccessTTL:    atExp.Sub(now),
		RefreshTTL:   rtExp.Sub(now),
	}, nil
}

func (a authService) Login(ctx context.Context, dto dto.LoginDTO) (model.TokenPair, error) {
	//TODO implement me
	panic("implement me")
}

func (a authService) Validate(ctx context.Context, dto dto.ValidateDTO) (model.User, error) {
	//TODO implement me
	panic("implement me")
}

func (a authService) Refresh(ctx context.Context, dto dto.RefreshDTO) (model.TokenPair, error) {
	//TODO implement me
	panic("implement me")
}

func (a authService) Logout(ctx context.Context, dto dto.LogoutDTO) error {
	//TODO implement me
	panic("implement me")
}
