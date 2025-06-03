package grpc

import (
	"context"
	"errors"
	"testing"

	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/dto"
	authErrors "github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/errors"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/model"
	authv1 "github.com/Miraines/MoonyAndStarry/auth-service/pkg/proto/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/status"
)

type stubSvc struct{}

func (stubSvc) Register(ctx context.Context, d dto.RegisterDTO) (model.TokenPair, error) {
	return model.TokenPair{}, authErrors.ErrAlreadyExists
}
func (stubSvc) Login(ctx context.Context, d dto.LoginDTO) (model.TokenPair, error) {
	return model.TokenPair{AccessToken: "a", RefreshToken: "b", UserId: uuid.New()}, nil
}
func (stubSvc) Validate(ctx context.Context, d dto.ValidateDTO) (model.User, error) {
	return model.User{}, nil
}
func (stubSvc) Refresh(ctx context.Context, d dto.RefreshDTO) (model.TokenPair, error) {
	return model.TokenPair{}, nil
}
func (stubSvc) Logout(ctx context.Context, d dto.LogoutDTO) error { return nil }

func TestHandler_Login(t *testing.T) {
	h := &Handler{svc: stubSvc{}}
	resp, err := h.Login(context.Background(), &authv1.LoginRequest{})
	if err != nil || resp.AccessToken == "" {
		t.Fatal("bad resp")
	}
}

func TestMapError(t *testing.T) {
	e := mapError(authErrors.ErrInvalidCredentials)
	if statusErr, ok := e.(interface{ GRPCStatus() *status.Status }); !ok || statusErr.GRPCStatus().Code() != 16 {
		t.Fatal("code")
	}
	if mapError(errors.New("x")).Error() == "" {
		t.Fatal("empty")
	}
}
