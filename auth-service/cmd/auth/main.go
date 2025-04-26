// cmd/http/main.go
package main

import (
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/service"
	"github.com/go-playground/validator"
	"net/http"
	"time"
	"unicode"

	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/dto"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/errors"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/jwt"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/config"
	myPostgresRepo "github.com/Miraines/MoonyAndStarry/auth-service/internal/repo/postgres"
	myRedisRepo "github.com/Miraines/MoonyAndStarry/auth-service/internal/repo/redis"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	// 1) Загрузить конфиг + логер
	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}
	zapLog, _ := zap.NewProduction()
	defer zapLog.Sync()

	// 2) GORM + Redis
	db, _ := gorm.Open(postgres.Open(cfg.DatabaseURL), &gorm.Config{})
	redisCli := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddress,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})

	// 3) Сервис
	userRepo := myPostgresRepo.NewPostgresUserRepo(db)
	tokenRepo := myRedisRepo.NewRedisTokenRepo(redisCli)
	jwtUtil, _ := jwt.NewJWTUtil(cfg)
	validate := validator.New()

	_ = validate.RegisterValidation("strongpwd", func(fl validator.FieldLevel) bool {
		pwd := fl.Field().String()
		if len(pwd) < 8 {
			return false
		}
		var hasUpper, hasDigit bool
		for _, r := range pwd {
			if unicode.IsUpper(r) {
				hasUpper = true
			}
			if unicode.IsDigit(r) {
				hasDigit = true
			}
		}
		return hasUpper && hasDigit
	})

	svc := service.NewAuthService(userRepo, tokenRepo, jwtUtil, cfg, validate)

	// 4) Gin-роутер
	router := gin.Default()
	router.POST("/register", func(c *gin.Context) {
		var body dto.RegisterDTO
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		pair, err := svc.Register(c.Request.Context(), body)
		if err != nil {
			handleError(c, err)
			return
		}
		c.JSON(http.StatusCreated, gin.H{
			"accessToken":  pair.AccessToken,
			"refreshToken": pair.RefreshToken,
			"expiresIn":    int(pair.AccessTTL.Seconds()),
			"userId":       pair.UserId.String(),
		})
	})

	router.POST("/login", func(c *gin.Context) {
		var body dto.LoginDTO
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		pair, err := svc.Login(c.Request.Context(), body)
		if err != nil {
			handleError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"accessToken":  pair.AccessToken,
			"refreshToken": pair.RefreshToken,
			"expiresIn":    int(pair.AccessTTL.Seconds()),
			"userId":       pair.UserId.String(),
		})
	})

	router.POST("/refresh", func(c *gin.Context) {
		var body dto.RefreshDTO
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		pair, err := svc.Refresh(c.Request.Context(), body)
		if err != nil {
			handleError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"accessToken":  pair.AccessToken,
			"refreshToken": pair.RefreshToken,
		})
	})

	router.POST("/logout", func(c *gin.Context) {
		var body dto.LogoutDTO
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := svc.Logout(c.Request.Context(), body); err != nil {
			handleError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "logged out"})
	})

	router.GET("/health", func(c *gin.Context) {
		// простая проверка — можно адаптировать по своему
		c.JSON(http.StatusOK, gin.H{"status": "ok", "time": time.Now().Unix()})
	})

	// 5) Запуск HTTP на 8080
	router.Run(":8080")
}

// handleError мапит ваши внутренние ошибки в HTTP-коды
func handleError(c *gin.Context, err error) {
	switch {
	case errors.IsInvalidArgument(err):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.IsInvalidCredentials(err):
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
	case errors.IsInvalidToken(err):
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
	case errors.IsAlreadyExists(err):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	case errors.IsNotFound(err):
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
	}
}
