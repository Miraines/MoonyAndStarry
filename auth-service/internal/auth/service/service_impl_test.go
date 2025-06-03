package service

import (
	"context"
	"testing"
	"time"

	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/dto"
	authErrors "github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/errors"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/jwt"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/model"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/config"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type userRepoStub struct{ users map[string]model.User }

func (u *userRepoStub) CreateUser(ctx context.Context, m model.User) (uuid.UUID, error) {
	u.users[m.ID.String()] = m
	return m.ID, nil
}
func (u *userRepoStub) GetUserByEmail(ctx context.Context, email string) (model.User, error) {
	for _, v := range u.users {
		if v.Email == email {
			return v, nil
		}
	}
	return model.User{}, authErrors.ErrNotFound
}
func (u *userRepoStub) GetUserByID(ctx context.Context, id uuid.UUID) (model.User, error) {
	v, ok := u.users[id.String()]
	if !ok {
		return model.User{}, authErrors.ErrNotFound
	}
	return v, nil
}
func (u *userRepoStub) UpdateUser(ctx context.Context, m model.User) error { return nil }
func (u *userRepoStub) DeleteUser(ctx context.Context, id uuid.UUID) error { return nil }
func (u *userRepoStub) GetUserByUsername(ctx context.Context, username string) (model.User, error) {
	return model.User{}, authErrors.ErrNotFound
}

type tokenRepoStub struct{ revoked map[string]bool }

func (t *tokenRepoStub) Revoke(ctx context.Context, jti string, exp time.Time) error {
	t.revoked[jti] = true
	return nil
}
func (t *tokenRepoStub) IsRevoked(ctx context.Context, jti string) (bool, error) {
	return t.revoked[jti], nil
}

func newSvc() (AuthService, *jwt.JwtUtilImpl, *tokenRepoStub) {
	ur := &userRepoStub{users: make(map[string]model.User)}
	tr := &tokenRepoStub{revoked: make(map[string]bool)}
	util, _ := jwt.NewJWTUtil(&config.Config{
		JWTPrivateKeyPath: "../jwt/testdata/priv.pem",
		JWTPublicKeyPath:  "../jwt/testdata/pub.pem",
		AccessTokenTTL:    time.Minute,
		RefreshTokenTTL:   time.Hour,
		Issuer:            "t",
		Audience:          "t",
	})
	v := validator.New()
	v.RegisterValidation("strongpwd", func(fl validator.FieldLevel) bool { return true })
	return NewAuthService(ur, tr, util, &config.Config{PasswordPepper: "p"}, v), util, tr
}

func TestAuthService_RegisterLogin(t *testing.T) {
	svc, _, _ := newSvc()
	ctx := context.Background()

	pair, err := svc.Register(ctx, dto.RegisterDTO{Email: "e@example.com", Password: "Aa1aaaaa", Username: "user"})
	require.NoError(t, err)
	require.NotEmpty(t, pair.AccessToken)

	pair2, err := svc.Login(ctx, dto.LoginDTO{Email: "e@example.com", Password: "Aa1aaaaa"})
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
	_, err := svc.Register(ctx, dto.RegisterDTO{Email: "user@example.com", Password: "Aa1aaaaa", Username: "user"})
	require.NoError(t, err)
	_, err = svc.Login(ctx, dto.LoginDTO{Email: "user@example.com", Password: "bad"})
	require.Error(t, err)
	require.True(t, authErrors.IsInvalidCredentials(err))
}

func TestAuthService_ValidateAndRefresh(t *testing.T) {
	svcIface, util, tr := newSvc()
	svc := svcIface
	ctx := context.Background()
	pair, err := svc.Register(ctx, dto.RegisterDTO{Email: "v@example.com", Password: "Aa1aaaaa", Username: "user"})
	require.NoError(t, err)
	user, err := svc.Validate(ctx, dto.ValidateDTO{AccessToken: pair.AccessToken})
	require.NoError(t, err)
	require.Equal(t, pair.UserId, user.ID)
	refreshed, err := svc.Refresh(ctx, dto.RefreshDTO{RefreshToken: pair.RefreshToken})
	require.NoError(t, err)
	// revoke old refresh token should mark revoked
	claims, _ := util.ValidateRefreshToken(pair.RefreshToken)
	revoked, _ := tr.IsRevoked(ctx, claims.ID)
	require.True(t, revoked)
	// logout should revoke token
	err = svc.Logout(ctx, dto.LogoutDTO{RefreshToken: refreshed.RefreshToken})
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
