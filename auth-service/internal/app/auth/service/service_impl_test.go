package service_test

import (
	"context"
	"errors"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/adapters/transport/http/dto"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/app/auth/jwt"
	appsvc "github.com/Miraines/MoonyAndStarry/auth-service/internal/app/auth/service"
	authErrors "github.com/Miraines/MoonyAndStarry/auth-service/internal/domain/auth/errors"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/domain/auth/model"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/infra/config"
	"testing"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

/* ──────────────────────────────── stubs ──────────────────────────────── */

type userRepoStub struct{ users map[string]model.User }

func (u *userRepoStub) CreateUser(_ context.Context, m model.User) (uuid.UUID, error) {
	u.users[m.ID.String()] = m
	return m.ID, nil
}
func (u *userRepoStub) GetUserByEmail(_ context.Context, email string) (model.User, error) {
	for _, v := range u.users {
		if v.Email == email {
			return v, nil
		}
	}
	return model.User{}, authErrors.ErrNotFound
}
func (u *userRepoStub) GetUserByID(_ context.Context, id uuid.UUID) (model.User, error) {
	v, ok := u.users[id.String()]
	if !ok {
		return model.User{}, authErrors.ErrNotFound
	}
	return v, nil
}
func (u *userRepoStub) UpdateUser(_ context.Context, _ model.User) error { return nil }
func (u *userRepoStub) DeleteUser(_ context.Context, _ uuid.UUID) error  { return nil }
func (u *userRepoStub) GetUserByUsername(_ context.Context, _ string) (model.User, error) {
	return model.User{}, authErrors.ErrNotFound
}
func (u *userRepoStub) GetUserByTelegramID(_ context.Context, id int64) (model.User, error) {
	for _, v := range u.users {
		if v.TelegramID == id {
			return v, nil
		}
	}
	return model.User{}, authErrors.ErrNotFound
}

type tokenRepoStub struct {
	revoked       map[string]bool
	accessRevoked map[string]bool
}

func (t *tokenRepoStub) Revoke(_ context.Context, jti string, _ time.Time) error {
	t.revoked[jti] = true
	return nil
}
func (t *tokenRepoStub) IsRevoked(_ context.Context, jti string) (bool, error) {
	return t.revoked[jti], nil
}
func (t *tokenRepoStub) RevokeAccess(_ context.Context, jti string, _ time.Time) error {
	t.accessRevoked[jti] = true
	return nil
}
func (t *tokenRepoStub) IsAccessRevoked(_ context.Context, jti string) (bool, error) {
	return t.accessRevoked[jti], nil
}
func (t *tokenRepoStub) Store(_ context.Context, jti string, _ time.Time) error {
	// по умолчанию токен активен («0»)
	if _, ok := t.revoked[jti]; !ok {
		t.revoked[jti] = false
	}
	return nil
}

type errTokenRepoStub struct{}

func (errTokenRepoStub) Revoke(ctx context.Context, jti string, exp time.Time) error {
	return errors.New("err")
}
func (errTokenRepoStub) IsRevoked(ctx context.Context, jti string) (bool, error) {
	return false, errors.New("err")
}
func (errTokenRepoStub) RevokeAccess(ctx context.Context, jti string, exp time.Time) error {
	return errors.New("err")
}
func (errTokenRepoStub) IsAccessRevoked(ctx context.Context, jti string) (bool, error) {
	return false, errors.New("err")
}
func (errTokenRepoStub) Store(_ context.Context, _ string, _ time.Time) error {
	return nil
}

/* ───────────────────────────── helpers ───────────────────────────── */

func newSvc() (appsvc.Service, *jwt.JwtUtilImpl, *tokenRepoStub) {
	ur := &userRepoStub{users: make(map[string]model.User)}
	tr := &tokenRepoStub{
		revoked:       make(map[string]bool),
		accessRevoked: make(map[string]bool),
	}

	util, _ := jwt.NewJWTUtil(&config.Config{
		JWTPrivateKeyPath: "../jwt/testdata/priv.pem",
		JWTPublicKeyPath:  "../jwt/testdata/pub.pem",
		AccessTokenTTL:    time.Minute,
		RefreshTokenTTL:   time.Hour,
		Issuer:            "test",
		Audience:          "test",
	})

	v := validator.New()
	_ = v.RegisterValidation("strongpwd", func(_ validator.FieldLevel) bool { return true })

	svc := appsvc.New(ur, tr, util, &config.Config{
		PasswordPepper:   "pepper",
		TelegramBotToken: "123456:dummy",
	}, v)

	return svc, util, tr
}

/* ───────────────────────────── tests ───────────────────────────── */

func TestAuthService_RegisterLogin(t *testing.T) {
	svc, _, _ := newSvc()
	ctx := context.Background()

	pair, err := svc.Register(ctx, dto.RegisterDTO{
		Email: "e@example.com", Password: "Aa1aaaaa", Username: "user",
	})
	require.NoError(t, err)
	require.NotEmpty(t, pair.AccessToken)

	pair2, err := svc.Login(ctx, dto.LoginDTO{
		Email: "e@example.com", Password: "Aa1aaaaa",
	})
	require.NoError(t, err)
	require.NotEmpty(t, pair2.RefreshToken)
}

func TestAuthService_RegisterInvalid(t *testing.T) {
	svc, _, _ := newSvc()
	_, err := svc.Register(context.Background(), dto.RegisterDTO{})
	require.Error(t, err)
	require.True(t, authErrors.IsInvalidArgument(err))
}

func TestAuthService_LoginInvalidPassword(t *testing.T) {
	svc, _, _ := newSvc()
	ctx := context.Background()

	_, _ = svc.Register(ctx, dto.RegisterDTO{
		Email: "u@example.com", Password: "Aa1aaaaa", Username: "user",
	})

	_, err := svc.Login(ctx, dto.LoginDTO{
		Email: "u@example.com", Password: "bad",
	})
	require.Error(t, err)
	require.True(t, authErrors.IsInvalidCredentials(err))
}

func TestAuthService_ValidateAndRefresh(t *testing.T) {
	svc, util, tr := newSvc()
	ctx := context.Background()

	pair, err := svc.Register(ctx, dto.RegisterDTO{
		Email: "v@example.com", Password: "Aa1aaaaa", Username: "user",
	})
	require.NoError(t, err)

	user, err := svc.Validate(ctx, dto.ValidateDTO{AccessToken: pair.AccessToken})
	require.NoError(t, err)
	require.Equal(t, pair.UserId, user.ID)

	refreshed, err := svc.Refresh(ctx, dto.RefreshDTO{RefreshToken: pair.RefreshToken})
	require.NoError(t, err)

	// refresh → старый токен должен быть отозван
	claims, _ := util.ValidateRefreshToken(pair.RefreshToken)
	revoked, _ := tr.IsRevoked(ctx, claims.ID)
	require.True(t, revoked)

	// logout должен отзывать и refresh, и access
	err = svc.Logout(ctx, dto.LogoutDTO{
		RefreshToken: refreshed.RefreshToken,
		AccessToken:  refreshed.AccessToken,
	})
	require.NoError(t, err)
}

func TestAuthService_ValidateInvalidToken(t *testing.T) {
	svc, _, _ := newSvc()
	_, err := svc.Validate(context.Background(), dto.ValidateDTO{AccessToken: "bad"})
	require.Error(t, err)
	require.True(t, authErrors.IsInvalidToken(err))
}

func TestAuthService_RefreshInvalidToken(t *testing.T) {
	svc, _, _ := newSvc()
	_, err := svc.Refresh(context.Background(), dto.RefreshDTO{RefreshToken: "bad"})
	require.Error(t, err)
	require.True(t, authErrors.IsInvalidToken(err))
}

type dupUserRepoStub struct{ *userRepoStub }

func (dupUserRepoStub) CreateUser(_ context.Context, _ model.User) (uuid.UUID, error) {
	return uuid.Nil, authErrors.ErrAlreadyExists
}

func TestAuthService_RegisterDuplicate(t *testing.T) {
	util, _ := jwt.NewJWTUtil(&config.Config{
		JWTPrivateKeyPath: "../jwt/testdata/priv.pem",
		JWTPublicKeyPath:  "../jwt/testdata/pub.pem",
		AccessTokenTTL:    time.Minute,
		RefreshTokenTTL:   time.Hour,
		Issuer:            "test",
		Audience:          "test",
	})

	v := validator.New()
	_ = v.RegisterValidation("strongpwd", func(_ validator.FieldLevel) bool { return true })

	svc := appsvc.New(
		dupUserRepoStub{&userRepoStub{}},
		&tokenRepoStub{revoked: map[string]bool{}, accessRevoked: map[string]bool{}},
		util,
		&config.Config{PasswordPepper: "pepper"},
		v,
	)

	_, err := svc.Register(context.Background(), dto.RegisterDTO{
		Email: "e@example.com", Password: "Aa1aaaaa", Username: "user",
	})
	require.Error(t, err)
	require.True(t, authErrors.IsAlreadyExists(err))
}

func TestAuthService_LoginUserNotFound(t *testing.T) {
	svc, _, _ := newSvc()
	_, err := svc.Login(context.Background(), dto.LoginDTO{
		Email: "none@example.com", Password: "p",
	})
	require.Error(t, err)
	require.True(t, authErrors.IsInvalidCredentials(err))
}

func TestAuthService_RefreshRevoked(t *testing.T) {
	svc, util, tr := newSvc()
	ctx := context.Background()

	pair, _ := svc.Register(ctx, dto.RegisterDTO{
		Email: "r@example.com", Password: "Aa1aaaaa", Username: "user",
	})

	claims, _ := util.ValidateRefreshToken(pair.RefreshToken)
	tr.revoked[claims.ID] = true

	_, err := svc.Refresh(ctx, dto.RefreshDTO{RefreshToken: pair.RefreshToken})
	require.Error(t, err)
	require.True(t, authErrors.IsInvalidToken(err))
}

func TestAuthService_LogoutInvalid(t *testing.T) {
	svc, _, _ := newSvc()
	err := svc.Logout(context.Background(), dto.LogoutDTO{
		RefreshToken: "bad",
		AccessToken:  "bad",
	})
	require.Error(t, err)
	require.True(t, authErrors.IsInvalidToken(err))
}

func TestAuthService_InternalErrors(t *testing.T) {
	util, _ := jwt.NewJWTUtil(&config.Config{
		JWTPrivateKeyPath: "../jwt/testdata/priv.pem",
		JWTPublicKeyPath:  "../jwt/testdata/pub.pem",
		AccessTokenTTL:    time.Minute,
		RefreshTokenTTL:   time.Hour,
		Issuer:            "test",
		Audience:          "test",
	})

	v := validator.New()
	_ = v.RegisterValidation("strongpwd", func(_ validator.FieldLevel) bool { return true })

	svc := appsvc.New(
		&userRepoStub{users: map[string]model.User{}},
		errTokenRepoStub{},
		util,
		&config.Config{PasswordPepper: "pepper"},
		v,
	)

	pair, err := svc.Register(context.Background(), dto.RegisterDTO{
		Email: "i@example.com", Password: "Aa1aaaaa", Username: "user",
	})
	require.NoError(t, err)

	_, err = svc.Refresh(context.Background(), dto.RefreshDTO{
		RefreshToken: pair.RefreshToken,
	})
	require.Error(t, err)
	require.True(t, authErrors.IsInternal(err))
}
