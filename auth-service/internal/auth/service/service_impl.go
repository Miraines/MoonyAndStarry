package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/dto"
	customErrors "github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/errors"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/jwt"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/model"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/telegram"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/config"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/repo"
	"github.com/alexedwards/argon2id"
	validate "github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

type authService struct {
	userRepo  repo.UserRepo
	tokenRepo repo.TokenRepo
	jwtUtil   jwt.JWTUtil
	cfg       *config.Config
	v         *validate.Validate
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
		UserId:       res,
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
		UserId:       user.ID,
	}, nil
}

func (a *authService) TelegramAuth(ctx context.Context, dto dto.TelegramAuthDTO) (model.TokenPair, error) {
	if dto.ID == 0 && dto.User != "" {
		var tgUser struct {
			ID        int64  `json:"id"`
			FirstName string `json:"first_name"`
			LastName  string `json:"last_name"`
			Username  string `json:"username"`
			PhotoURL  string `json:"photo_url"`
		}
		if err := json.Unmarshal([]byte(dto.User), &tgUser); err != nil {
			return model.TokenPair{}, customErrors.NewInvalidArgument(err.Error())
		}
		dto.ID = tgUser.ID
		if dto.FirstName == "" {
			dto.FirstName = tgUser.FirstName
		}
		if dto.LastName == "" {
			dto.LastName = tgUser.LastName
		}
		if dto.Username == "" {
			dto.Username = tgUser.Username
		}
		if dto.PhotoURL == "" {
			dto.PhotoURL = tgUser.PhotoURL
		}
	}

	if err := a.v.Struct(dto); err != nil {
		return model.TokenPair{}, customErrors.NewInvalidArgument(err.Error())
	}

	var checkMap map[string]string
	if dto.User != "" {
		checkMap = map[string]string{
			"auth_date": fmt.Sprintf("%d", dto.AuthDate),
			"query_id":  dto.QueryID,
			"user":      dto.User,
		}
	} else {
		checkMap = map[string]string{
			"auth_date":  fmt.Sprintf("%d", dto.AuthDate),
			"first_name": dto.FirstName,
			"id":         fmt.Sprintf("%d", dto.ID),
			"last_name":  dto.LastName,
			"username":   dto.Username,
			"photo_url":  dto.PhotoURL,
		}
	}

	if !telegram.CheckAuth(checkMap, dto.Hash, a.cfg.TelegramBotToken) {
		return model.TokenPair{}, customErrors.ErrInvalidCredentials
	}
	user, err := a.userRepo.GetUserByTelegramID(ctx, dto.ID)
	if err != nil && !errors.Is(err, customErrors.ErrNotFound) {
		return model.TokenPair{}, customErrors.WrapInternal(err, "TelegramAuth")
	}

	if errors.Is(err, customErrors.ErrNotFound) {
		email := fmt.Sprintf("tg%d@telegram.local", dto.ID)
		passHash, _ := argon2id.CreateHash(uuid.NewString()+a.cfg.PasswordPepper, argon2id.DefaultParams)
		user = model.User{
			ID:              uuid.New(),
			Email:           email,
			PasswordHash:    passHash,
			Username:        dto.Username,
			TelegramID:      dto.ID,
			FirstName:       dto.FirstName,
			LastName:        dto.LastName,
			ProfilePhotoURL: dto.PhotoURL,
		}
		if user.Username == "" {
			user.Username = fmt.Sprintf("tg%d", dto.ID)
		}
		if _, err := a.userRepo.CreateUser(ctx, user); err != nil {
			return model.TokenPair{}, err
		}
	} else {
		user.Username = dto.Username
		user.FirstName = dto.FirstName
		user.LastName = dto.LastName
		user.ProfilePhotoURL = dto.PhotoURL
		_ = a.userRepo.UpdateUser(ctx, user)
	}

	accessToken, atExp, _, err := a.jwtUtil.GenerateAccessToken(user.ID, []string{"user"})
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "TelegramAuth")
	}

	refreshToken, rtExp, _, err := a.jwtUtil.GenerateRefreshToken(user.ID)
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "TelegramAuth")
	}

	now := time.Now()

	return model.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		AccessTTL:    atExp.Sub(now),
		RefreshTTL:   rtExp.Sub(now),
		UserId:       user.ID,
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
		UserId:       uid,
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
