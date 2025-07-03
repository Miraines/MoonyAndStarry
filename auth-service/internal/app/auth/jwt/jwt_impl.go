package jwt

import (
	"crypto/rsa"
	"errors"
	customErrors "github.com/Miraines/MoonyAndStarry/auth-service/internal/domain/auth/errors"
	jwt2 "github.com/Miraines/MoonyAndStarry/auth-service/internal/domain/auth/jwt"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/infra/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"os"
	"time"
)

type JwtUtilImpl struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	accessTTL  time.Duration
	refreshTTL time.Duration
	issuer     string
	audience   string
}

func NewJWTUtil(cfg *config.Config) (*JwtUtilImpl, error) {
	privPem, err := os.ReadFile(cfg.JWTPrivateKeyPath)
	if err != nil {
		return nil, customErrors.WrapInternal(err, "read private key")
	}
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privPem)
	if err != nil {
		return nil, customErrors.WrapInternal(err, "parse private key")
	}

	pubPem, err := os.ReadFile(cfg.JWTPublicKeyPath)
	if err != nil {
		return nil, customErrors.WrapInternal(err, "read public key")
	}
	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(pubPem)
	if err != nil {
		return nil, customErrors.WrapInternal(err, "parse public key")
	}

	return &JwtUtilImpl{
		privateKey: privKey,
		publicKey:  pubKey,
		accessTTL:  cfg.AccessTokenTTL,
		refreshTTL: cfg.RefreshTokenTTL,
		issuer:     cfg.Issuer,
		audience:   cfg.Audience,
	}, nil
}

func (j *JwtUtilImpl) GenerateAccessToken(userID uuid.UUID, roles []string) (token string, exp time.Time, jti string, err error) {
	jti = uuid.NewString()
	now := time.Now()

	claims := jwt2.AccessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			Issuer:    j.issuer,
			Audience:  jwt.ClaimStrings{j.audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(j.accessTTL)),
			ID:        jti,
		},
		Roles: roles,
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(j.privateKey)
	if err != nil {
		return "", time.Time{}, "", customErrors.WrapInternal(err, "sign access token")
	}

	return signed, claims.ExpiresAt.Time, jti, nil
}

func (j *JwtUtilImpl) GenerateRefreshToken(userID uuid.UUID) (token string, exp time.Time, jti string, err error) {
	jti = uuid.NewString()
	now := time.Now()

	claims := jwt2.RefreshClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			Issuer:    j.issuer,
			Audience:  jwt.ClaimStrings{j.audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(j.refreshTTL)),
			ID:        jti,
		},
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(j.privateKey)
	if err != nil {
		return "", time.Time{}, "", customErrors.WrapInternal(err, "sign refresh token")
	}

	return signed, claims.ExpiresAt.Time, jti, nil
}

func (j *JwtUtilImpl) ValidateAccessToken(raw string) (jwt2.AccessClaims, error) {
	token, err := jwt.ParseWithClaims(raw, &jwt2.AccessClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, customErrors.ErrInvalidToken
		}
		return j.publicKey, nil
	}, jwt.WithIssuedAt(), jwt.WithLeeway(2*time.Minute))

	if err != nil || !token.Valid {
		return jwt2.AccessClaims{}, customErrors.ErrInvalidToken
	}

	claims, ok := token.Claims.(*jwt2.AccessClaims)
	if !ok {
		return jwt2.AccessClaims{}, customErrors.WrapInternal(
			errors.New("claims not AccessClaims"), "ValidateAccessToken",
		)
	}

	if j.issuer != "" && claims.Issuer != j.issuer {
		return jwt2.AccessClaims{}, customErrors.ErrInvalidToken
	}

	if j.audience != "" {
		okAudi := false
		for _, a := range claims.Audience {
			if a == j.audience {
				okAudi = true
				break
			}
		}
		if !okAudi {
			return jwt2.AccessClaims{}, customErrors.ErrInvalidToken
		}
	}

	return *claims, nil
}

func (j *JwtUtilImpl) ValidateRefreshToken(raw string) (jwt2.RefreshClaims, error) {
	token, err := jwt.ParseWithClaims(raw, &jwt2.RefreshClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, customErrors.ErrInvalidToken
		}
		return j.publicKey, nil
	}, jwt.WithIssuedAt(), jwt.WithLeeway(2*time.Minute))

	if err != nil || !token.Valid {
		return jwt2.RefreshClaims{}, customErrors.ErrInvalidToken
	}

	claims, ok := token.Claims.(*jwt2.RefreshClaims)

	if !ok {
		return jwt2.RefreshClaims{}, customErrors.WrapInternal(
			errors.New("claims not RefreshClaims"), "ValidateRefreshToken")
	}

	if j.issuer != "" && claims.Issuer != j.issuer {
		return jwt2.RefreshClaims{}, customErrors.ErrInvalidToken
	}

	if j.audience != "" {
		okAudi := false
		for _, a := range claims.Audience {
			if a == j.audience {
				okAudi = true
				break
			}
		}
		if !okAudi {
			return jwt2.RefreshClaims{}, customErrors.ErrInvalidToken
		}
	}

	return *claims, nil
}
