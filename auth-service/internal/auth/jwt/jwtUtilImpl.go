package jwt

import (
	"crypto/rsa"
	"errors"
	customErrors "github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/errors"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"io/ioutil"
	"time"
)

type jwtUtilImpl struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	accessTTL  time.Duration
	refreshTTL time.Duration
	issuer     string
	audience   string
}

func NewJWTUtil(cfg *config.Config) (*jwtUtilImpl, error) {
	privPem, err := ioutil.ReadFile(cfg.JWTPrivateKeyPath)
	if err != nil {
		return nil, customErrors.WrapInternal(err, "read private key")
	}
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privPem)
	if err != nil {
		return nil, customErrors.WrapInternal(err, "parse private key")
	}

	pubPem, err := ioutil.ReadFile(cfg.JWTPublicKeyPath)
	if err != nil {
		return nil, customErrors.WrapInternal(err, "read public key")
	}
	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(pubPem)
	if err != nil {
		return nil, customErrors.WrapInternal(err, "parse public key")
	}

	return &jwtUtilImpl{
		privateKey: privKey,
		publicKey:  pubKey,
		accessTTL:  cfg.AccessTokenTTL,
		refreshTTL: cfg.RefreshTokenTTL,
	}, nil
}

func (j *jwtUtilImpl) GenerateAccessToken(userID string, roles []string) (token string, exp time.Time, jti string, err error) {
	jti = uuid.NewString()
	now := time.Now()

	claims := AccessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(j.accessTTL)),
			Issuer:    j.issuer,
			Audience:  jwt.ClaimStrings{j.audience},
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

func (j *jwtUtilImpl) GenerateRefreshToken(userID string) (token string, exp time.Time, jti string, err error) {
	jti = uuid.NewString()
	now := time.Now()

	claims := RefreshClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(j.refreshTTL)),
			Issuer:    j.issuer,
			Audience:  jwt.ClaimStrings{j.audience},
			ID:        jti,
		},
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(j.privateKey)
	if err != nil {
		return "", time.Time{}, "", customErrors.WrapInternal(err, "sign refresh token")
	}

	return signed, claims.ExpiresAt.Time, jti, nil
}

func (j *jwtUtilImpl) ValidateAccessToken(raw string) (AccessClaims, error) {
	token, err := jwt.ParseWithClaims(raw, &AccessClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, customErrors.ErrInvalidToken
		}
		return j.publicKey, nil
	})

	if err != nil {
		return AccessClaims{}, customErrors.ErrInvalidToken
	}

	if !token.Valid {
		return AccessClaims{}, customErrors.ErrInvalidToken
	}

	claims, ok := token.Claims.(*AccessClaims)
	if !ok {
		return AccessClaims{}, customErrors.WrapInternal(
			errors.New("claims not AccessClaims"), "ValidateAccessToken",
		)
	}

	return *claims, nil
}

func (j *jwtUtilImpl) ValidateRefreshToken(raw string) (RefreshClaims, error) {
	token, err := jwt.ParseWithClaims(raw, &RefreshClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, customErrors.ErrInvalidToken
		}
		return j.publicKey, nil
	})

	if err != nil {
		return RefreshClaims{}, customErrors.ErrInvalidToken
	}

	if !token.Valid {
		return RefreshClaims{}, customErrors.ErrInvalidToken
	}

	claims, ok := token.Claims.(*RefreshClaims)
	if !ok {
		return RefreshClaims{}, customErrors.WrapInternal(errors.New("claims not RefreshClaims"), "ValidateRefreshToken")
	}

	return *claims, nil
}
