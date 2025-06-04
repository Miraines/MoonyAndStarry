package main

import (
	"context"
	telegramloginwidget "github.com/LipsarHQ/go-telegram-login-widget"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unicode"

	stdErr "errors"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/dto"
	authErrors "github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/errors"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/jwt"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/service"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/config"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/migrate"
	myPostgresRepo "github.com/Miraines/MoonyAndStarry/auth-service/internal/repo/postgres"
	myRedisRepo "github.com/Miraines/MoonyAndStarry/auth-service/internal/repo/redis"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/server"
	myGrpc "github.com/Miraines/MoonyAndStarry/auth-service/internal/transport/grpc"
	"github.com/gin-contrib/cors"
)

func main() {
	zapLog, err := zap.NewProduction()
	if err != nil {
		panic("failed to init logger: " + err.Error())
	}
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
		return hasUpper && hasDigit
	})

	userRepo := myPostgresRepo.NewPostgresUserRepo(db)
	tokenRepo := myRedisRepo.NewRedisTokenRepo(redisCli)
	jwtUtil, err := jwt.NewJWTUtil(cfg)
	if err != nil {
		zapLog.Fatal("failed to init JWT util", zap.Error(err))
	}
	svc := service.NewAuthService(userRepo, tokenRepo, jwtUtil, cfg, validate)

	go func() {
		grpcHandler := myGrpc.NewHandler(svc, db, redisCli)
		if err := server.StartGRPCServer(cfg, grpcHandler, zapLog); err != nil {
			zapLog.Fatal("gRPC server error", zap.Error(err))
		}
	}()

	router := gin.Default()

	router.Use(func(c *gin.Context) {
		start := time.Now()
		c.Next()
		latency := time.Since(start)
		status := c.Writer.Status()
		log.Printf(
			"HTTP %s %s | status=%d | latency=%s | clientIP=%s",
			c.Request.Method,
			c.Request.URL.Path,
			status,
			latency,
			c.ClientIP(),
		)
	})

	corsConfig := cors.Config{
		AllowOrigins: []string{
			"https://miraines.github.io",
			"https://7d24-84-19-3-112.ngrok-free.app",
		}, AllowMethods: []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: false,
	}
	router.Use(cors.New(corsConfig))

	router.POST("/register", func(c *gin.Context) {
		var body dto.RegisterDTO
		if err := c.ShouldBindJSON(&body); err != nil {
			log.Printf("HTTP /register bind error: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		log.Printf("HTTP /register payload: email=%s, username=%s", body.Email, body.Username)

		pair, err := svc.Register(c.Request.Context(), body)
		if err != nil {
			log.Printf("Service Register error: %v", err)
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
			log.Printf("HTTP /login bind error: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		log.Printf("HTTP /login payload: email=%s", body.Email)

		pair, err := svc.Login(c.Request.Context(), body)
		if err != nil {
			log.Printf("Service Login error: %v", err)
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

	router.GET("/login/telegram", func(c *gin.Context) {
		log.Printf("=== TelegramAuth BEGIN, raw query: %s", c.Request.URL.RawQuery)

		// 1) Биндим GET-параметры в DTO
		var body dto.TelegramAuthDTO
		if err := c.ShouldBindQuery(&body); err != nil {
			log.Printf("BindQuery error: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if initData := c.Query("init_data"); initData != "" {
			body.InitData = initData
			log.Printf("Detected init_data: %q", body.InitData)
		}

		if body.InitData == "" {
			if body.TelegramID == 0 {
				body.TelegramID = body.ID
			}
			log.Printf("Classic Login Widget: TelegramID = %d", body.TelegramID)

			values := c.Request.URL.Query()

			authData, err := telegramloginwidget.NewFromQuery(values)
			if err != nil {
				log.Printf("Telegram Login Widget NewFromQuery error: %v", err)
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid query parameters"})
				return
			}

			if err := authData.Check(cfg.TelegramBotToken); err != nil {
				log.Printf("Telegram Login Widget Check failed: %v", err)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
				return
			}
		}

		pair, err := svc.TelegramAuth(c.Request.Context(), body)
		if err != nil {
			log.Printf("Service TelegramAuth error: %v", err)
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

	router.POST("/login/telegram", func(c *gin.Context) {
		log.Printf("=== TelegramAuth POST BEGIN, content-type: %s", c.GetHeader("Content-Type"))

		var body dto.TelegramAuthDTO

		contentType := c.GetHeader("Content-Type")

		if contentType == "application/json" {
			if err := c.ShouldBindJSON(&body); err != nil {
				log.Printf("JSON bind error: %v", err)
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
		} else {
			if err := c.ShouldBind(&body); err != nil {
				log.Printf("Form bind error: %v", err)
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
		}

		log.Printf("Bound data: InitData length=%d, TelegramID=%d, AuthDate=%d, Hash present=%t",
			len(body.InitData), body.TelegramID, body.AuthDate, body.Hash != "")

		hasInitData := body.InitData != ""
		hasWebWidgetData := (body.TelegramID != 0 || body.ID != 0) && body.AuthDate != 0 && body.Hash != ""

		if !hasInitData && !hasWebWidgetData {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing required telegram auth data"})
			return
		}

		if body.TelegramID == 0 && body.ID != 0 {
			body.TelegramID = body.ID
		}

		log.Printf("Final data: InitData=%t, TelegramID=%d, AuthDate=%d, Hash=%s",
			body.InitData != "", body.TelegramID, body.AuthDate, body.Hash)

		pair, err := svc.TelegramAuth(c, body)
		if err != nil {
			log.Printf("Service TelegramAuth error: %v", err)
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

	router.POST("/logout", func(c *gin.Context) {
		var body dto.LogoutDTO
		if err := c.ShouldBindJSON(&body); err != nil {
			log.Printf("HTTP /logout bind error: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		log.Printf("HTTP /logout payload: refreshToken=%s", body.RefreshToken)

		if err := svc.Logout(c.Request.Context(), body); err != nil {
			log.Printf("Service Logout error: %v", err)
			handleError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "logged out"})
	})

	router.GET("/health", func(c *gin.Context) {
		log.Printf("HTTP /health called")
		c.JSON(http.StatusOK, gin.H{"status": "ok", "time": time.Now().Unix()})
	})

	srv := &http.Server{Addr: ":8080", Handler: router}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !stdErr.Is(err, http.ErrServerClosed) {
			zapLog.Error("http server error", zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctxShutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctxShutdown); err != nil {
		zapLog.Error("shutdown error", zap.Error(err))
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
