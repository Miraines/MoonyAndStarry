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

func (a *authService) Login(ctx context.Context, dto dto.LoginDTO) (model.TokenPair, error) {
	if err := a.v.Struct(dto); err != nil {
		return model.TokenPair{}, customErrors.NewInvalidArgument(err.Error())
	}

	user, err := a.userRepo.GetUserByEmail(ctx, dto.Email)
	if errors.Is(err, customErrors.ErrNotFound) {
		return model.TokenPair{}, customErrors.ErrInvalidCredentials
	}

	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "Login")
	}

	ok, err := argon2id.ComparePasswordAndHash(dto.Password+a.cfg.PasswordPepper, user.PasswordHash)
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "Login")
	}
	if !ok {
		return model.TokenPair{}, customErrors.ErrInvalidCredentials
	}

	accessToken, atExp, _, err := a.jwtUtil.GenerateAccessToken(user.ID, []string{"user"})
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "Login")
	}

	refreshToken, rtExp, _, err := a.jwtUtil.GenerateRefreshToken(user.ID)
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "Login")
	}

	now := time.Now()

	return model.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		AccessTTL:    atExp.Sub(now),
		RefreshTTL:   rtExp.Sub(now),
	}, nil
}

func (a *authService) Validate(ctx context.Context, dto dto.ValidateDTO) (model.User, error) {

	if err := a.v.Struct(dto); err != nil {
		return model.User{}, customErrors.NewInvalidArgument(err.Error())
	}

	claims, err := a.jwtUtil.ValidateAccessToken(dto.AccessToken)
	if err != nil {
		return model.User{}, customErrors.ErrInvalidToken
	}

	revoked, err := a.tokenRepo.IsRevoked(ctx, claims.ID)
	if err != nil {
		return model.User{}, customErrors.WrapInternal(err, "Validate")
	}
	if revoked {
		return model.User{}, customErrors.ErrInvalidToken
	}

	uid, err := uuid.Parse(claims.Subject)

	if err != nil {
		return model.User{}, customErrors.ErrInvalidToken
	}
	user, err := a.userRepo.GetUserByID(ctx, uid)

	if err != nil {
		return model.User{}, customErrors.ErrInvalidToken
	}
	return user, nil
}

func (a *authService) Refresh(ctx context.Context, dto dto.RefreshDTO) (model.TokenPair, error) {

	if err := a.v.Struct(dto); err != nil {
		return model.TokenPair{}, customErrors.NewInvalidArgument(err.Error())
	}

	claims, err := a.jwtUtil.ValidateRefreshToken(dto.RefreshToken)
	if err != nil {
		return model.TokenPair{}, customErrors.ErrInvalidToken
	}

	revoked, err := a.tokenRepo.IsRevoked(ctx, claims.ID)
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "Refresh")
	}
	if revoked {
		return model.TokenPair{}, customErrors.ErrInvalidToken
	}

	err = a.tokenRepo.Revoke(ctx, claims.ID, claims.ExpiresAt.Time)
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "Refresh")
	}

	uid, err := uuid.Parse(claims.Subject)
	if err != nil {
		return model.TokenPair{}, customErrors.ErrInvalidToken
	}

	accessToken, atExp, _, err := a.jwtUtil.GenerateAccessToken(uid, []string{"user"})
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "Refresh")
	}

	refreshToken, rtExp, _, err := a.jwtUtil.GenerateRefreshToken(uid)
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "Refresh")
	}

	now := time.Now()

	return model.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		AccessTTL:    atExp.Sub(now),
		RefreshTTL:   rtExp.Sub(now),
	}, nil
}

func (a *authService) Logout(ctx context.Context, dto dto.LogoutDTO) error {

	if err := a.v.Struct(dto); err != nil {
		return customErrors.NewInvalidArgument(err.Error())
	}

	claims, err := a.jwtUtil.ValidateRefreshToken(dto.RefreshToken)
	if err != nil {
		return customErrors.ErrInvalidToken
	}

	err = a.tokenRepo.Revoke(ctx, claims.ID, claims.ExpiresAt.Time)
	if err != nil {
		return customErrors.WrapInternal(err, "Logout")
	}

	return nil
}
