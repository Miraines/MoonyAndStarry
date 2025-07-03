package service

import (
	"context"
	"errors"
	"fmt"
	telegramloginwidget "github.com/LipsarHQ/go-telegram-login-widget"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/adapters/transport/http/dto"
	customErrors "github.com/Miraines/MoonyAndStarry/auth-service/internal/domain/auth/errors"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/domain/auth/jwt"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/domain/auth/model"
	repo "github.com/Miraines/MoonyAndStarry/auth-service/internal/domain/auth/repo"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/infra/config"
	"github.com/go-playground/validator/v10"
	initdata "github.com/telegram-mini-apps/init-data-golang"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/google/uuid"
)

var argonParams = &argon2id.Params{
	Memory:      64 * 1024, // 64 MiB
	Iterations:  2,
	Parallelism: 4,
	SaltLength:  16,
	KeyLength:   32,
}

type authService struct {
	userRepo  repo.UserRepo
	tokenRepo repo.TokenRepo
	jwtUtil   jwt.JWTUtil
	cfg       *config.Config
	v         *validator.Validate
}

type Service interface {
	Register(context.Context, dto.RegisterDTO) (model.TokenPair, error)
	Login(context.Context, dto.LoginDTO) (model.TokenPair, error)
	TelegramAuth(context.Context, dto.TelegramAuthDTO) (model.TokenPair, error)
	Validate(context.Context, dto.ValidateDTO) (model.User, error)
	Refresh(context.Context, dto.RefreshDTO) (model.TokenPair, error)
	Logout(context.Context, dto.LogoutDTO) error
}

func New(
	ur repo.UserRepo,
	tr repo.TokenRepo,
	jm jwt.JWTUtil,
	cfg *config.Config,
	v *validator.Validate,
) Service {
	return &authService{
		userRepo: ur, tokenRepo: tr, jwtUtil: jm, cfg: cfg, v: v,
	}
}

func (a *authService) Register(ctx context.Context, dto dto.RegisterDTO) (model.TokenPair, error) {

	if err := a.v.Struct(dto); err != nil {
		return model.TokenPair{}, customErrors.NewInvalidArgument(err.Error())
	}

	passwordHash, err := argon2id.CreateHash(dto.Password+a.cfg.PasswordPepper, argonParams)

	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "Register")
	}

	user := model.User{
		Username:     dto.Username,
		ID:           uuid.New(),
		Email:        dto.Email,
		PasswordHash: passwordHash,
	}
	if _, err = a.userRepo.CreateUser(ctx, user); err != nil {
		if errors.Is(err, customErrors.ErrAlreadyExists) {
			return model.TokenPair{}, customErrors.ErrAlreadyExists
		}
		return model.TokenPair{}, customErrors.WrapInternal(err, "Register")
	}

	at, atExp, _, err := a.jwtUtil.GenerateAccessToken(user.ID, []string{"user"})
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "GenerateAccessToken")
	}
	rt, rtExp, jti, err := a.jwtUtil.GenerateRefreshToken(user.ID)
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "GenerateRefreshToken")
	}

	if err = a.tokenRepo.Store(ctx, jti, rtExp); err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "StoreRefresh")
	}

	now := time.Now()

	return model.TokenPair{
		AccessToken:     at,
		RefreshToken:    rt,
		AccessTTL:       atExp.Sub(now),
		RefreshTTL:      rtExp.Sub(now),
		UserId:          user.ID,
		RefreshTokenJTI: jti,
	}, nil
}

func (a *authService) Login(ctx context.Context, dto dto.LoginDTO) (model.TokenPair, error) {
	if err := a.v.Struct(dto); err != nil {
		return model.TokenPair{}, customErrors.NewInvalidArgument(err.Error())
	}

	user, err := a.userRepo.GetUserByEmail(ctx, dto.Email)
	switch {
	case errors.Is(err, customErrors.ErrNotFound):
		return model.TokenPair{}, customErrors.ErrInvalidCredentials
	case err != nil:
		return model.TokenPair{}, customErrors.WrapInternal(err, "Login")
	}

	ok, err := argon2id.ComparePasswordAndHash(dto.Password+a.cfg.PasswordPepper, user.PasswordHash)
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "Login")
	}
	if !ok {
		return model.TokenPair{}, customErrors.ErrInvalidCredentials
	}

	at, atExp, _, err := a.jwtUtil.GenerateAccessToken(user.ID, []string{"user"})
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "GenerateAccessToken")
	}
	rt, rtExp, jti, err := a.jwtUtil.GenerateRefreshToken(user.ID)
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "GenerateRefreshToken")
	}

	if err = a.tokenRepo.Store(ctx, jti, rtExp); err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "StoreRefresh")
	}

	now := time.Now()

	return model.TokenPair{
		AccessToken:     at,
		RefreshToken:    rt,
		AccessTTL:       atExp.Sub(now),
		RefreshTTL:      rtExp.Sub(now),
		UserId:          user.ID,
		RefreshTokenJTI: jti,
	}, nil
}

func (a *authService) TelegramAuth(
	ctx context.Context,
	in dto.TelegramAuthDTO,
) (model.TokenPair, error) {

	const ttl = 24 * time.Hour
	botID, err := strconv.ParseInt(strings.Split(a.cfg.TelegramBotToken, ":")[0], 10, 64)

	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "invalid telegram bot token")
	}
	// 1) Сценарий mini-app: подпись содержится в init_data
	if in.InitData != "" {
		if err := initdata.ValidateThirdParty(in.InitData, botID, ttl); err != nil {
			return model.TokenPair{}, customErrors.ErrInvalidCredentials
		}
		idata, err := initdata.Parse(in.InitData)
		if err != nil {
			return model.TokenPair{}, customErrors.NewInvalidArgument("malformed init_data")
		}
		if time.Since(idata.AuthDate()) > ttl {
			return model.TokenPair{}, customErrors.ErrInvalidCredentials
		}
		return a.upsertUserAndIssueTokens(ctx,
			idata.User.ID,
			idata.User.Username,
			idata.User.FirstName,
			idata.User.LastName,
			idata.User.PhotoURL)
	}

	// 2) Сценарий login-widget: подпись идёт в query-параметре hash
	if in.Hash == "" || in.AuthDate == 0 || in.TelegramID == 0 {
		return model.TokenPair{}, customErrors.NewInvalidArgument("missing hash/auth_date/id")
	}

	// Собираем оригинальные параметры в том же порядке, как их формирует Telegram.
	q := url.Values{}
	q.Set("auth_date", fmt.Sprint(in.AuthDate))
	q.Set("hash", in.Hash)
	q.Set("id", fmt.Sprint(in.TelegramID))
	if in.FirstName != "" {
		q.Set("first_name", in.FirstName)
	}
	if in.LastName != "" {
		q.Set("last_name", in.LastName)
	}
	if in.PhotoURL != "" {
		q.Set("photo_url", in.PhotoURL)
	}
	if in.Username != "" {
		q.Set("username", in.Username)
	}

	authData, err := telegramloginwidget.NewFromQuery(q)
	if err != nil || authData.Check(a.cfg.TelegramBotToken) != nil {
		return model.TokenPair{}, customErrors.ErrInvalidCredentials
	}
	if time.Since(time.Unix(in.AuthDate, 0)) > ttl {
		return model.TokenPair{}, customErrors.ErrInvalidCredentials
	}

	return a.upsertUserAndIssueTokens(ctx,
		in.TelegramID, in.Username, in.FirstName, in.LastName, in.PhotoURL)
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
			if err := a.userRepo.UpdateUser(ctx, user); err != nil {
				return model.TokenPair{}, customErrors.WrapInternal(err, "UpdateUser")
			}
		}

	case errors.Is(err, customErrors.ErrNotFound):
		email := fmt.Sprintf("tg%d@telegram.local", tgID)
		passHash, _ := argon2id.CreateHash(uuid.NewString()+a.cfg.PasswordPepper, argonParams)
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

	return a.issueTokens(ctx, user.ID)
}

func (a *authService) Validate(ctx context.Context, dto dto.ValidateDTO) (model.User, error) {

	if err := a.v.Struct(dto); err != nil {
		return model.User{}, customErrors.NewInvalidArgument(err.Error())
	}

	claims, err := a.jwtUtil.ValidateAccessToken(dto.AccessToken)
	if err != nil {
		return model.User{}, customErrors.ErrInvalidToken
	}

	revoked, err := a.tokenRepo.IsAccessRevoked(ctx, claims.ID)
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

	if err = a.tokenRepo.Revoke(ctx, claims.ID, claims.ExpiresAt.Time); err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "Refresh")
	}

	if dto.AccessToken != "" {
		if acc, errAcc := a.jwtUtil.ValidateAccessToken(dto.AccessToken); errAcc == nil {
			_ = a.tokenRepo.RevokeAccess(ctx, acc.ID, acc.ExpiresAt.Time)
		}
	}

	uid, _ := uuid.Parse(claims.Subject)
	return a.issueTokens(ctx, uid) // сохранение JTI происходит внутри
}

func (a *authService) Logout(ctx context.Context, dto dto.LogoutDTO) error {

	if err := a.v.Struct(dto); err != nil {
		return customErrors.NewInvalidArgument(err.Error())
	}

	claims, err := a.jwtUtil.ValidateRefreshToken(dto.RefreshToken)
	if err != nil {
		return customErrors.ErrInvalidToken
	}

	if err := a.tokenRepo.Revoke(ctx, claims.ID, claims.ExpiresAt.Time); err != nil {
		return customErrors.WrapInternal(err, "Logout")
	}

	acc, err := a.jwtUtil.ValidateAccessToken(dto.AccessToken)
	if err == nil { // access может уже истечь – это не ошибка
		_ = a.tokenRepo.RevokeAccess(ctx, acc.ID, acc.ExpiresAt.Time)
	}
	return nil
}

func (a *authService) issueTokens(ctx context.Context, uid uuid.UUID) (model.TokenPair, error) {
	at, atExp, _, err := a.jwtUtil.GenerateAccessToken(uid, []string{"user"})
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "GenerateAccessToken")
	}
	rt, rtExp, jti, err := a.jwtUtil.GenerateRefreshToken(uid)
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "GenerateRefreshToken")
	}
	if err = a.tokenRepo.Store(ctx, jti, rtExp); err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "StoreRefresh")
	}

	now := time.Now()
	return model.TokenPair{
		AccessToken:     at,
		RefreshToken:    rt,
		AccessTTL:       atExp.Sub(now),
		RefreshTTL:      rtExp.Sub(now),
		UserId:          uid,
		RefreshTokenJTI: jti,
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
