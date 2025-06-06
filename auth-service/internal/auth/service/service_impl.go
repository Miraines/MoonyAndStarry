package service

import (
	"context"
	"errors"
	"fmt"
	initdata "github.com/telegram-mini-apps/init-data-golang"
	"strconv"
	"strings"
	"time"

	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/dto"
	customErrors "github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/errors"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/jwt"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/model"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/config"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/repo"
	"github.com/alexedwards/argon2id"
	validate "github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

const (
	// Время жизни init_data (24 часа)
	initDataTTL = 24 * time.Hour
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

func (a *authService) TelegramAuth(
	ctx context.Context,
	in dto.TelegramAuthDTO,
) (model.TokenPair, error) {

	if in.InitData != "" {
		botID, _ := strconv.ParseInt(strings.Split(a.cfg.TelegramBotToken, ":")[0], 10, 64)

		if err := initdata.ValidateThirdParty(in.InitData, botID, initDataTTL); err != nil {
			return model.TokenPair{}, customErrors.ErrInvalidCredentials
		}

		idata, err := initdata.Parse(in.InitData)
		if err != nil {
			return model.TokenPair{}, customErrors.NewInvalidArgument("malformed init_data")
		}

		return a.upsertUserAndIssueTokens(
			ctx,
			idata.User.ID,
			idata.User.Username,
			idata.User.FirstName,
			idata.User.LastName,
			idata.User.PhotoURL,
		)
	}

	return a.upsertUserAndIssueTokens(
		ctx,
		in.TelegramID,
		in.Username,
		in.FirstName,
		in.LastName,
		in.PhotoURL,
	)
}

func (a *authService) upsertUserAndIssueTokens(
	ctx context.Context,
	tgID int64,
	username, firstName, lastName, photoURL string,
) (model.TokenPair, error) {

	user, err := a.userRepo.GetUserByTelegramID(ctx, tgID)
	switch {
	case err == nil:
		if updateUser(&user, username, firstName, lastName, photoURL) {
			_ = a.userRepo.UpdateUser(ctx, user)
		}

	case errors.Is(err, customErrors.ErrNotFound):
		email := fmt.Sprintf("tg%d@telegram.local", tgID)
		passHash, _ := argon2id.CreateHash(uuid.NewString()+a.cfg.PasswordPepper, argon2id.DefaultParams)

		user = model.User{
			ID:              uuid.New(),
			Email:           email,
			PasswordHash:    passHash,
			Username:        nonEmpty(username, fmt.Sprintf("tg%d", tgID)),
			TelegramID:      tgID,
			FirstName:       firstName,
			LastName:        lastName,
			ProfilePhotoURL: photoURL,
		}
		if _, err := a.userRepo.CreateUser(ctx, user); err != nil {
			return model.TokenPair{}, customErrors.WrapInternal(err, "CreateUser")
		}

	default:
		return model.TokenPair{}, customErrors.WrapInternal(err, "GetUserByTelegramID")
	}

	at, atExp, _, err := a.jwtUtil.GenerateAccessToken(user.ID, []string{"user"})
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "GenerateAccessToken")
	}
	rt, rtExp, _, err := a.jwtUtil.GenerateRefreshToken(user.ID)
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "GenerateRefreshToken")
	}

	now := time.Now()
	return model.TokenPair{
		AccessToken:  at,
		RefreshToken: rt,
		AccessTTL:    atExp.Sub(now),
		RefreshTTL:   rtExp.Sub(now),
		UserId:       user.ID,
	}, nil
}

func updateUser(u *model.User, username, fn, ln, photo string) (changed bool) {
	if username != "" && u.Username != username {
		u.Username, changed = username, true
	}
	if fn != "" && u.FirstName != fn {
		u.FirstName, changed = fn, true
	}
	if ln != "" && u.LastName != ln {
		u.LastName, changed = ln, true
	}
	if photo != "" && u.ProfilePhotoURL != photo {
		u.ProfilePhotoURL = photo
		changed = true
	}
	return
}

func nonEmpty(s, fallback string) string {
	if s != "" {
		return s
	}
	return fallback
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
