// cmd/auth/main.go
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
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
	// Инициализация логгера
	zapLog, err := zap.NewProduction()
	if err != nil {
		panic("failed to init logger: " + err.Error())
	}
	defer zapLog.Sync()

	cfg, err := config.Load()
	if err != nil {
		zapLog.Fatal("failed to load config", zap.Error(err))
	}

	// 2) GORM + Redis
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

	// 3) Сервис и валидатор
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

	// <<< Запуск gRPC-сервера в горутине с логами
	go func() {
		grpcHandler := myGrpc.NewHandler(svc, db, redisCli)
		if err := server.StartGRPCServer(cfg, grpcHandler, zapLog); err != nil {
			zapLog.Fatal("gRPC server error", zap.Error(err))
		}
	}()

	// 4) Gin-роутер для HTTP/REST
	router := gin.Default()

	// Логируем каждый HTTP-запрос
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
		// 0) Логируем raw-query для дебага
		log.Printf("=== TelegramAuth BEGIN, raw query: %s", c.Request.URL.RawQuery)

		// 1) Биндим query-строку в структуру
		var body dto.TelegramAuthDTO
		if err := c.ShouldBindQuery(&body); err != nil {
			log.Printf("BindQuery error: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		// Логируем, что получилось после биндинга
		log.Printf("After BindQuery: ID=%d, InitData=%q, User=%q, AuthDate=%d, Hash=%q",
			body.ID, body.InitData, body.User, body.AuthDate, body.Hash)

		// 2) Если пришёл init_data (Web App), пробуем раскодировать и распарсить
		if body.InitData != "" {
			decodedInit, err := url.QueryUnescape(body.InitData)
			if err != nil {
				log.Printf("Failed to QueryUnescape init_data: %v", err)
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid init_data encoding"})
				return
			}
			parsed, err := url.ParseQuery(decodedInit)
			if err != nil {
				log.Printf("Failed to ParseQuery init_data: %v", err)
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid init_data format"})
				return
			}
			// Если в init_data прямо лежат поля auth_date, hash, id, first_name и т.д.
			if authDateStr := parsed.Get("auth_date"); authDateStr != "" {
				body.AuthDate, _ = strconv.ParseInt(authDateStr, 10, 64)
			}
			if hash := parsed.Get("hash"); hash != "" {
				body.Hash = hash
			}
			if userJSON := parsed.Get("user"); body.User == "" && userJSON != "" {
				body.User = userJSON
			}
			if queryID := parsed.Get("query_id"); body.QueryID == "" && queryID != "" {
				body.QueryID = queryID
			}
			// В случае Web-widget: id, first_name, last_name, username, photo_url
			if body.ID == 0 {
				if idStr := parsed.Get("id"); idStr != "" {
					body.ID, _ = strconv.ParseInt(idStr, 10, 64)
				}
			}
			if body.FirstName == "" {
				body.FirstName = parsed.Get("first_name")
			}
			if body.LastName == "" {
				body.LastName = parsed.Get("last_name")
			}
			if body.Username == "" {
				body.Username = parsed.Get("username")
			}
			if body.PhotoURL == "" {
				body.PhotoURL = parsed.Get("photo_url")
			}
			log.Printf("After parsing init_data: ID=%d, User=%q, AuthDate=%d, Hash=%q", body.ID, body.User, body.AuthDate, body.Hash)
		}

		// 3) Если пришёл user (Mini-App), пробуем распарсить JSON
		if body.User != "" {
			decodedUser, err := url.QueryUnescape(body.User)
			if err != nil {
				log.Printf("Failed to QueryUnescape user JSON: %v", err)
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user JSON encoding"})
				return
			}
			var u struct {
				ID        int64  `json:"id"`
				FirstName string `json:"first_name"`
				LastName  string `json:"last_name"`
				Username  string `json:"username"`
				PhotoURL  string `json:"photo_url"`
			}
			if err := json.Unmarshal([]byte(decodedUser), &u); err != nil {
				log.Printf("json.Unmarshal user JSON error: %v (raw: %q)", err, decodedUser)
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user JSON"})
				return
			}
			// Заполняем DTO полями из JSON
			body.TelegramID = u.ID
			if body.FirstName == "" {
				body.FirstName = u.FirstName
			}
			if body.LastName == "" {
				body.LastName = u.LastName
			}
			if body.Username == "" {
				body.Username = u.Username
			}
			if body.PhotoURL == "" {
				body.PhotoURL = u.PhotoURL
			}
			log.Printf("After parsing user JSON: TelegramID=%d, FirstName=%s, Username=%s", body.TelegramID, body.FirstName, body.Username)
		}

		// 4) Для классического Web-виджета: если TelegramID всё ещё не установлен, берём его из ID
		if body.TelegramID == 0 {
			body.TelegramID = body.ID
		}
		log.Printf("Final before validation: TelegramID=%d, AuthDate=%d, Hash=%q",
			body.TelegramID, body.AuthDate, body.Hash)

		// 5) Ручная проверка обязательных полей
		switch {
		case body.TelegramID == 0:
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing id or user"})
			return
		case body.AuthDate == 0:
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing auth_date"})
			return
		case body.Hash == "":
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing hash"})
			return
		}

		// 6) Бизнес-логика: проверка подписи и создание/получение пользователя
		pair, err := svc.TelegramAuth(c, dto.TelegramAuthDTO{
			ID:         body.TelegramID,
			FirstName:  body.FirstName,
			LastName:   body.LastName,
			Username:   body.Username,
			PhotoURL:   body.PhotoURL,
			User:       body.User,
			QueryID:    body.QueryID,
			AuthDate:   body.AuthDate,
			Hash:       body.Hash,
			TelegramID: body.TelegramID,
		})
		if err != nil {
			log.Printf("Service TelegramAuth error: %v", err)
			handleError(c, err)
			return
		}

		// 7) Возвращаем токены
		c.JSON(http.StatusOK, gin.H{
			"accessToken":  pair.AccessToken,
			"refreshToken": pair.RefreshToken,
			"expiresIn":    int(pair.AccessTTL.Seconds()),
			"userId":       pair.UserId.String(),
		})
	})

	router.POST("/login/telegram", func(c *gin.Context) {
		log.Printf("=== TelegramAuth POST BEGIN, content-type: %s, len=%d",
			c.GetHeader("Content-Type"), c.Request.ContentLength)

		// 1) Получаем RAW данные без автоматического декодирования
		var body dto.TelegramAuthDTO

		// Для form-data и query параметров используем ShouldBindQuery + ShouldBindWith
		if err := c.ShouldBindQuery(&body); err != nil {
			log.Printf("Query bind error: %v", err)
		}

		// Для JSON используем обычный Bind
		if c.GetHeader("Content-Type") == "application/json" {
			if err := c.ShouldBindJSON(&body); err != nil {
				log.Printf("JSON bind error: %v", err)
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
		} else {
			// Для form-data получаем init_data вручную чтобы избежать автодекодирования
			if initData := c.PostForm("init_data"); initData != "" {
				body.InitData = initData // Сохраняем как есть, без декодирования
			}
			if initData := c.Query("init_data"); initData != "" {
				body.InitData = initData // Сохраняем как есть, без декодирования
			}
		}

		log.Printf("Raw bound data: InitData length=%d, TelegramID=%d, AuthDate=%d, Hash=%q",
			len(body.InitData), body.TelegramID, body.AuthDate, body.Hash)

		// 2) Минимальная валидация - НЕ трогаем данные, только проверяем наличие
		hasInitData := body.InitData != ""
		hasWebWidgetData := (body.TelegramID != 0 || body.ID != 0) && body.AuthDate != 0 && body.Hash != ""

		if !hasInitData && !hasWebWidgetData {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing required telegram auth data"})
			return
		}

		// Fallback для веб-виджета (если нужно)
		if !hasInitData && body.TelegramID == 0 && body.ID != 0 {
			body.TelegramID = body.ID
		}

		// 3) Передаем данные в сервис БЕЗ ИЗМЕНЕНИЙ
		serviceDTO := dto.TelegramAuthDTO{
			// Основные поля - как есть
			InitData:   body.InitData, // RAW данные без декодирования!
			TelegramID: body.TelegramID,
			AuthDate:   body.AuthDate,
			Hash:       body.Hash,

			// Дополнительные поля
			ID:        body.ID,
			FirstName: body.FirstName,
			LastName:  body.LastName,
			Username:  body.Username,
			PhotoURL:  body.PhotoURL,
			User:      body.User,
			QueryID:   body.QueryID,
		}

		log.Printf("=== DEBUG: Sending RAW data to service ===")
		log.Printf("InitData (first 100 chars): %.100s", serviceDTO.InitData)
		log.Printf("InitData length: %d", len(serviceDTO.InitData))
		log.Printf("TelegramID: %d", serviceDTO.TelegramID)
		log.Printf("AuthDate: %d", serviceDTO.AuthDate)
		log.Printf("Hash: %s", serviceDTO.Hash)
		log.Printf("=============================================")

		// 4) Вызываем сервис
		pair, err := svc.TelegramAuth(c, serviceDTO)
		if err != nil {
			log.Printf("Service TelegramAuth error: %v", err)
			handleError(c, err)
			return
		}

		// 5) Возвращаем результат
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

	// 5) HTTP server with graceful shutdown
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
