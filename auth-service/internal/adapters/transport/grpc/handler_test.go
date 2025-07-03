package grpc

import (
	"context"
	"errors"
	"github.com/Miraines/MoonyAndStarry/auth-service/api/proto/v1"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/adapters/transport/http/dto"
	authErrors "github.com/Miraines/MoonyAndStarry/auth-service/internal/domain/auth/errors"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/domain/auth/model"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

/* ───────────────────────────── stub service ───────────────────────────── */

type stubSvc struct{}

func (stubSvc) Register(ctx context.Context, _ dto.RegisterDTO) (model.TokenPair, error) {
	return model.TokenPair{}, authErrors.ErrAlreadyExists
}
func (stubSvc) Login(ctx context.Context, _ dto.LoginDTO) (model.TokenPair, error) {
	return model.TokenPair{AccessToken: "acc", RefreshToken: "ref", UserId: uuid.New()}, nil
}
func (stubSvc) TelegramAuth(ctx context.Context, _ dto.TelegramAuthDTO) (model.TokenPair, error) {
	return model.TokenPair{AccessToken: "tgAcc", RefreshToken: "tgRef", UserId: uuid.New()}, nil
}
func (stubSvc) Validate(context.Context, dto.ValidateDTO) (model.User, error) {
	return model.User{}, nil
}
func (stubSvc) Refresh(context.Context, dto.RefreshDTO) (model.TokenPair, error) {
	return model.TokenPair{}, nil
}
func (stubSvc) Logout(context.Context, dto.LogoutDTO) error { return nil }

/* ───────────────────────────── tests ───────────────────────────── */

func TestHandler_Login(t *testing.T) {
	h := &Handler{svc: stubSvc{}}

	resp, err := h.Login(context.Background(), &authv1.LoginRequest{
		Email: "e@example.com", Password: "pass",
	})
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("Login response has empty AccessToken")
	}
}

func TestHandler_TelegramAuth(t *testing.T) {
	h := &Handler{svc: stubSvc{}}

	resp, err := h.TelegramAuth(context.Background(), &authv1.TelegramAuthRequest{
		Id: 1, Username: "u",
	})
	if err != nil {
		t.Fatalf("TelegramAuth returned error: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("TelegramAuth response has empty AccessToken")
	}
}

func TestHandler_Register_AlreadyExists(t *testing.T) {
	h := &Handler{svc: stubSvc{}}

	_, err := h.Register(context.Background(), &authv1.RegisterRequest{
		Email:    "e@example.com",
		Password: "p",
		Username: "u",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.AlreadyExists {
		t.Fatalf("expected AlreadyExists, got %s", st.Code())
	}
}

func TestMapError(t *testing.T) {
	if st, _ := status.FromError(mapError(authErrors.ErrInvalidCredentials)); st.Code() != codes.Unauthenticated {
		t.Fatal("ErrInvalidCredentials should map to Unauthenticated")
	}
	if st, _ := status.FromError(mapError(errors.New("x"))); st.Code() != codes.Internal {
		t.Fatal("generic error should map to Internal")
	}
}
