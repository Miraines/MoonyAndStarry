package jwt

import (
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/config"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"testing"
	"time"
)

func testConfig() *config.Config {
	return &config.Config{
		JWTPrivateKeyPath: "testdata/priv.pem",
		JWTPublicKeyPath:  "testdata/pub.pem",
		AccessTokenTTL:    time.Minute,
		RefreshTokenTTL:   time.Hour,
		Issuer:            "test",
		Audience:          "test",
	}
}

func TestJWTUtil_GenerateValidate(t *testing.T) {
	util, err := NewJWTUtil(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	uid := uuid.New()
	token, exp, jti, err := util.GenerateAccessToken(uid, []string{"role"})
	if err != nil || exp.IsZero() || jti == "" {
		t.Fatalf("bad generate: %v", err)
	}
	claims, err := util.ValidateAccessToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != uid.String() {
		t.Fatalf("want %s got %s", uid, claims.Subject)
	}
}

func TestJWTUtil_ValidateErrors(t *testing.T) {
	util, _ := NewJWTUtil(testConfig())
	// invalid token string
	_, err := util.ValidateAccessToken("bad")
	if err == nil {
		t.Fatal("expected error")
	}
	// token signed with other key
	other, _ := NewJWTUtil(&config.Config{JWTPrivateKeyPath: "testdata/priv.pem", JWTPublicKeyPath: "testdata/pub.pem", AccessTokenTTL: time.Minute, RefreshTokenTTL: time.Hour, Issuer: "wrong", Audience: "test"})
	tok, _, _, _ := other.GenerateAccessToken(uuid.New(), nil)
	if _, err := util.ValidateAccessToken(tok); err == nil {
		t.Fatal("expected issuer error")
	}
}

func TestJWTUtil_RefreshCycle(t *testing.T) {
	util, _ := NewJWTUtil(testConfig())
	uid := uuid.New()
	rTok, exp, jti, err := util.GenerateRefreshToken(uid)
	if err != nil || exp.IsZero() || jti == "" {
		t.Fatalf("bad generate: %v", err)
	}
	cl, err := util.ValidateRefreshToken(rTok)
	if err != nil || cl.Subject != uid.String() {
		t.Fatalf("validate error: %v", err)
	}
}

func TestJWTUtil_InvalidAlg(t *testing.T) {
	util, _ := NewJWTUtil(testConfig())
	token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "1"}).SignedString([]byte("x"))
	if _, err := util.ValidateAccessToken(token); err == nil {
		t.Fatal("expected invalid alg")
	}
}

func TestJWTUtil_InvalidAudience(t *testing.T) {
	cfg := testConfig()
	util, _ := NewJWTUtil(cfg)
	otherCfg := *cfg
	otherCfg.Audience = "other"
	other, _ := NewJWTUtil(&otherCfg)
	tok, _, _, _ := other.GenerateAccessToken(uuid.New(), nil)
	if _, err := util.ValidateAccessToken(tok); err == nil {
		t.Fatal("expected audience error")
	}
}

func TestJWTUtil_RefreshInvalidAlg(t *testing.T) {
	util, _ := NewJWTUtil(testConfig())
	token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "1"}).SignedString([]byte("x"))
	if _, err := util.ValidateRefreshToken(token); err == nil {
		t.Fatal("expected invalid alg")
	}
}

func TestJWTUtil_RefreshInvalidAudience(t *testing.T) {
	cfg := testConfig()
	util, _ := NewJWTUtil(cfg)
	otherCfg := *cfg
	otherCfg.Audience = "other"
	other, _ := NewJWTUtil(&otherCfg)
	tok, _, _, _ := other.GenerateRefreshToken(uuid.New())
	if _, err := util.ValidateRefreshToken(tok); err == nil {
		t.Fatal("expected audience error")
	}
}

func TestJWTUtil_InvalidClaimType(t *testing.T) {
	util, _ := NewJWTUtil(testConfig())
	// create token with wrong claims type for access token validation
	token, _ := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"foo": "bar"}).SignedString(util.privateKey)
	if _, err := util.ValidateAccessToken(token); err == nil {
		t.Fatal("expected type error")
	}
}
