package jwt

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"time"
)

type AccessClaims struct {
	jwt.RegisteredClaims
	Roles []string `json:"roles"`
	Jti   string   `json:"jti"`
}

type RefreshClaims struct {
	jwt.RegisteredClaims
	Jti string `json:"jti"`
}

type JWTUtil interface {
	GenerateAccessToken(userID uuid.UUID, roles []string) (token string, exp time.Time, jti string, err error)
	GenerateRefreshToken(userID uuid.UUID) (token string, exp time.Time, jti string, err error)
	ValidateAccessToken(token string) (claims AccessClaims, err error)
	ValidateRefreshToken(token string) (claims RefreshClaims, err error)
}
