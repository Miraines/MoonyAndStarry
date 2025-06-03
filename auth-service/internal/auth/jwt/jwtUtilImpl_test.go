package jwt

import (
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/config"
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
