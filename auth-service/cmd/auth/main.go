package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	myPostgresRepo "github.com/Miraines/MoonyAndStarry/auth-service/internal/adapters/db/postgres"
	myRedisRepo "github.com/Miraines/MoonyAndStarry/auth-service/internal/adapters/db/redis"
	myGrpc "github.com/Miraines/MoonyAndStarry/auth-service/internal/adapters/transport/grpc"
	grpcmw "github.com/Miraines/MoonyAndStarry/auth-service/internal/adapters/transport/grpc/middleware"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/adapters/transport/http/dto"
	httpmw "github.com/Miraines/MoonyAndStarry/auth-service/internal/adapters/transport/http/middleware"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/app/auth/jwt"
	appsvc "github.com/Miraines/MoonyAndStarry/auth-service/internal/app/auth/service"
	authErrors "github.com/Miraines/MoonyAndStarry/auth-service/internal/domain/auth/errors"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/domain/auth/model"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/infra/config"
	lg "github.com/Miraines/MoonyAndStarry/auth-service/internal/infra/log"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/infra/migrate"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/infra/server"
	"golang.org/x/sync/errgroup"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/gin-contrib/cors"
)

func issueTokens(c *gin.Context, pair model.TokenPair, domain string) {
	// Access
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(
		"access_token",
		pair.AccessToken,
		int(pair.AccessTTL.Seconds()),
		"/",
		domain,
		true, // secure
		true, // httpOnly
	)

	// Refresh
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(
		"refresh_token",
		pair.RefreshToken,
		int(pair.RefreshTTL.Seconds()),
		"/",
		domain,
		true,
		true,
	)

	c.JSON(http.StatusOK, gin.H{
		"expiresIn": int(pair.AccessTTL.Seconds()),
		"userId":    pair.UserId.String(),
	})
}

func main() {
	zapLog := lg.Must(os.Getenv("debug"))
	defer zapLog.Sync()

	cfg, err := config.Load()
	if err != nil {
		zapLog.Fatal("failed to load config", zap.Error(err))
	}

	db, err := gorm.Open(postgres.Open(cfg.DatabaseURL), &gorm.Config{})
	if err != nil {
		zapLog.Fatal("failed to connect to database", zap.Error(err))
	}
	sqlDB, err := db.DB()
	if err != nil {
		zapLog.Fatal("db handle", zap.Error(err))
	}
	defer sqlDB.Close()
	if err := migrate.Up(sqlDB); err != nil {
		zapLog.Fatal("run migrations", zap.Error(err))
	}

	redisCli := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddress,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
	defer redisCli.Close()

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
		return utf8.RuneCountInString(pwd) >= 8 && hasUpper && hasDigit
	})

	userRepo := myPostgresRepo.NewPostgresUserRepo(db)
	tokenRepo := myRedisRepo.NewRedisTokenRepo(redisCli)
	jwtUtil, err := jwt.NewJWTUtil(cfg)
	if err != nil {
		zapLog.Fatal("failed to init JWT util", zap.Error(err))
	}
	svc := appsvc.New(userRepo, tokenRepo, jwtUtil, cfg, validate)

	grpcHandler := myGrpc.NewHandler(svc, db, redisCli)

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(httpmw.RequestLogger(zapLog))
	router.Use(grpcmw.NewHTTPRateLimitPerIP(50, 100, 10_000, time.Hour))

	corsConfig := cors.Config{
		AllowOrigins: cfg.AllowedOrigins,
		AllowMethods: []string{"GET", "POST", "OPTIONS"},
		AllowHeaders: []string{
			"Origin", "Content-Type", "Accept",
			"Authorization",
			"X-Requested-With",
		},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: cfg.AllowCredentials,
		MaxAge:           12 * time.Hour,
	}
	router.Use(cors.New(corsConfig))

	router.POST("/register", func(c *gin.Context) {
		var body dto.RegisterDTO
		if err := c.ShouldBindJSON(&body); err != nil {
			log.Printf("HTTP /register bind error: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		zapLog.Info("/register",
			zap.String("user", fmt.Sprintf("%x", sha256.Sum256([]byte(body.Email)))),
		)
		pair, err := svc.Register(c.Request.Context(), body)
		if err != nil {
			handleError(c, err)
			return
		}
		issueTokens(c, pair, cfg.CookieDomain)
	})

	router.POST("/login", func(c *gin.Context) {
		var body dto.LoginDTO
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		zapLog.Info("/login",
			zap.String("user", fmt.Sprintf("%x", sha256.Sum256([]byte(body.Email)))),
		)

		pair, err := svc.Login(c.Request.Context(), body)
		if err != nil {
			handleError(c, err)
			return
		}
		issueTokens(c, pair, cfg.CookieDomain)
	})

	router.GET("/login/telegram", func(c *gin.Context) {
		zapLog.Info("telegram_auth_get",
			zap.String("raw_query", c.Request.URL.RawQuery),
		)

		var body dto.TelegramAuthDTO
		if err := c.ShouldBindQuery(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// init_data может прилететь как «init_data=…» — сохраняем
		if initData := c.Query("init_data"); initData != "" {
			body.InitData = initData
		}

		if body.TelegramID == 0 && body.ID != 0 {
			body.TelegramID = body.ID
		}

		pair, err := svc.TelegramAuth(c.Request.Context(), body)
		if err != nil {
			handleError(c, err)
			return
		}

		issueTokens(c, pair, cfg.CookieDomain)
	})

	router.POST("/login/telegram", func(c *gin.Context) {
		var body dto.TelegramAuthDTO

		// JSON или form-urlencoded — поддерживаем оба варианта
		switch c.GetHeader("Content-Type") {
		case "application/json":
			if err := c.ShouldBindJSON(&body); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
		default:
			if err := c.ShouldBind(&body); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
		}

		if body.TelegramID == 0 && body.ID != 0 {
			body.TelegramID = body.ID
		}

		zapLog.Info("telegram_login_post",
			zap.Int64("telegram_id", body.TelegramID),
			zap.String("origin", c.GetHeader("Origin")),
			zap.String("ac_requested", c.GetHeader("Access-Control-Request-Headers")),
			zap.String("content_type", c.GetHeader("Content-Type")),
		)

		pair, err := svc.TelegramAuth(c.Request.Context(), body)
		if err != nil {
			handleError(c, err)
			return
		}

		issueTokens(c, pair, cfg.CookieDomain)
	})

	router.POST("/logout", func(c *gin.Context) {
		var body dto.LogoutDTO
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		zapLog.Info("/logout")

		if err := svc.Logout(c.Request.Context(), body); err != nil {
			handleError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "logged out"})
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
		issueTokens(c, pair, cfg.CookieDomain)
	})

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "time": time.Now().Unix()})
	})

	srv := &http.Server{Addr: ":8080", Handler: router}
	rootCtx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(rootCtx)

	g.Go(func() error {
		return server.StartGRPCServer(ctx, cfg, grpcHandler, zapLog)
	})

	g.Go(func() error {
		if err := srv.ListenAndServeTLS(cfg.HTTPSCertFile, cfg.HTTPSKeyFile); err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	})

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	zapLog.Info("shutdown signal received")
	cancel()

	ctxShutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctxShutdown); err != nil {
		zapLog.Error("shutdown error", zap.Error(err))
	}
	if err := g.Wait(); err != nil {
		zapLog.Error("server terminated", zap.Error(err))
	}
}

func handleError(c *gin.Context, err error) {
	switch {
	case authErrors.IsInvalidArgument(err):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case authErrors.IsInvalidCredentials(err):
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
	case authErrors.IsInvalidToken(err):
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
	case authErrors.IsAlreadyExists(err):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	case authErrors.IsNotFound(err):
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
	}
}
