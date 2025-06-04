package grpc

import (
	"context"
	"github.com/pkg/errors"
	"log"

	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/dto"
	customErrors "github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/errors"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/service"
	authv1 "github.com/Miraines/MoonyAndStarry/auth-service/pkg/proto/v1"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"
	"time"
)

type Handler struct {
	authv1.UnimplementedAuthServer
	svc      service.AuthService
	db       *gorm.DB
	redisCli *redis.Client
}

func NewHandler(svc service.AuthService, db *gorm.DB, redisCli *redis.Client) *Handler {
	return &Handler{
		svc:      svc,
		db:       db,
		redisCli: redisCli,
	}
}

func (h *Handler) Register(ctx context.Context, req *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {
	log.Printf("gRPC Register called: email=%s, username=%s", req.Email, req.Username)

	pair, err := h.svc.Register(ctx, dto.RegisterDTO{
		Email:    req.Email,
		Password: req.Password,
		Username: req.Username,
	})
	if err != nil {
		log.Printf("gRPC Register error: %v", err)
		return nil, mapError(err)
	}

	return &authv1.RegisterResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		AccessTtl:    int64(pair.AccessTTL.Seconds()),
		RefreshTtl:   int64(pair.RefreshTTL.Seconds()),
		UserId:       pair.UserId.String(),
	}, nil
}

func (h *Handler) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	log.Printf("gRPC Login called: email=%s", req.Email)

	pair, err := h.svc.Login(ctx, dto.LoginDTO{
		Email:    req.Email,
		Password: req.Password,
	})
	if err != nil {
		log.Printf("gRPC Login error: %v", err)
		return nil, mapError(err)
	}

	return &authv1.LoginResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		AccessTtl:    int64(pair.AccessTTL.Seconds()),
		RefreshTtl:   int64(pair.RefreshTTL.Seconds()),
		UserId:       pair.UserId.String(),
	}, nil
}

func (h *Handler) TelegramAuth(ctx context.Context, req *authv1.TelegramAuthRequest) (*authv1.LoginResponse, error) {
	log.Printf("gRPC TelegramAuth called: id=%d first_name=%s last_name=%s username=%s photo_url=%s auth_date=%d hash=%s",
		req.Id, req.FirstName, req.LastName, req.Username, req.PhotoUrl, req.AuthDate, req.Hash)

	pair, err := h.svc.TelegramAuth(ctx, dto.TelegramAuthDTO{
		ID:        req.Id,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Username:  req.Username,
		PhotoURL:  req.PhotoUrl,
		AuthDate:  req.AuthDate,
		Hash:      req.Hash,
	})
	if err != nil {
		log.Printf("gRPC TelegramAuth error: %v", err)
		return nil, mapError(err)
	}
	return &authv1.LoginResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		AccessTtl:    int64(pair.AccessTTL.Seconds()),
		RefreshTtl:   int64(pair.RefreshTTL.Seconds()),
		UserId:       pair.UserId.String(),
	}, nil
}

func (h *Handler) Validate(ctx context.Context, req *authv1.ValidateRequest) (*authv1.ValidateResponse, error) {
	log.Printf("gRPC Validate called: accessToken=%s", req.AccessToken)

	user, err := h.svc.Validate(ctx, dto.ValidateDTO{
		AccessToken: req.AccessToken,
	})
	if err != nil {
		log.Printf("gRPC Validate error: %v", err)
		return nil, mapError(err)
	}

	return &authv1.ValidateResponse{
		UserId:    user.ID.String(),
		Timestamp: user.UpdatedAt.Unix(),
	}, nil
}

func (h *Handler) Refresh(ctx context.Context, req *authv1.RefreshRequest) (*authv1.RefreshResponse, error) {
	log.Printf("gRPC Refresh called: refreshToken=%s", req.RefreshToken)

	pair, err := h.svc.Refresh(ctx, dto.RefreshDTO{
		RefreshToken: req.RefreshToken,
	})
	if err != nil {
		log.Printf("gRPC Refresh error: %v", err)
		return nil, mapError(err)
	}

	return &authv1.RefreshResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
	}, nil
}

func (h *Handler) Logout(ctx context.Context, req *authv1.LogoutRequest) (*authv1.LogoutResponse, error) {
	log.Printf("gRPC Logout called: refreshToken=%s", req.RefreshToken)

	err := h.svc.Logout(ctx, dto.LogoutDTO{RefreshToken: req.RefreshToken})
	if err != nil {
		log.Printf("gRPC Logout error: %v", err)
		return nil, mapError(err)
	}

	return &authv1.LogoutResponse{Success: true}, nil
}

func (h *Handler) HealthCheck(ctx context.Context, req *authv1.HealthCheckRequest) (*authv1.HealthCheckResponse, error) {
	log.Printf("gRPC HealthCheck called")

	if err := h.db.WithContext(ctx).Exec("SELECT 1").Error; err != nil {
		log.Printf("gRPC HealthCheck DB error: %v", err)
		return &authv1.HealthCheckResponse{Status: authv1.HealthStatus_NOT_SERVING}, nil
	}
	if _, err := h.redisCli.Ping(ctx).Result(); err != nil {
		log.Printf("gRPC HealthCheck Redis error: %v", err)
		return &authv1.HealthCheckResponse{Status: authv1.HealthStatus_NOT_SERVING}, nil
	}
	return &authv1.HealthCheckResponse{
		Status:    authv1.HealthStatus_SERVING,
		Version:   "v1.0.0",
		Timestamp: time.Now().Unix(),
	}, nil
}

func mapError(err error) error {
	switch {
	case errors.Is(err, customErrors.ErrInvalidArgument):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, customErrors.ErrInvalidCredentials):
		return status.Error(codes.Unauthenticated, "invalid credentials")
	case errors.Is(err, customErrors.ErrInvalidToken):
		return status.Error(codes.Unauthenticated, "invalid token")
	case errors.Is(err, customErrors.ErrAlreadyExists):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, customErrors.ErrNotFound):
		return status.Error(codes.NotFound, err.Error())
	default:
		return status.Error(codes.Internal, "internal error")
	}
}
