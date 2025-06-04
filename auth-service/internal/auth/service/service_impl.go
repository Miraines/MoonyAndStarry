package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"time"

	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/dto"
	customErrors "github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/errors"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/jwt"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/model"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/auth/telegram"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/config"
	"github.com/Miraines/MoonyAndStarry/auth-service/internal/repo"
	"github.com/alexedwards/argon2id"
	validate "github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

type authService struct {
	userRepo  repo.UserRepo
	tokenRepo repo.TokenRepo
	jwtUtil   jwt.JWTUtil
	cfg       *config.Config
	v         *validate.Validate
}

func (a *authService) Register(ctx context.Context, dto dto.RegisterDTO) (model.TokenPair, error) {

	if err := a.v.Struct(dto); err != nil {
		return model.TokenPair{}, customErrors.NewInvalidArgument(err.Error())
	}

	passwordHash, err := argon2id.CreateHash(dto.Password+a.cfg.PasswordPepper, argon2id.DefaultParams)

	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "Register")
	}

	user := model.User{
		Username:     dto.Username,
		ID:           uuid.New(),
		Email:        dto.Email,
		PasswordHash: passwordHash,
	}
	res, err := a.userRepo.CreateUser(ctx, user)

	if err != nil {
		if errors.Is(err, customErrors.ErrAlreadyExists) {
			return model.TokenPair{}, customErrors.ErrAlreadyExists
		}

		return model.TokenPair{}, customErrors.WrapInternal(err, "Register")
	}

	accessToken, atExp, _, err := a.jwtUtil.GenerateAccessToken(res, []string{"user"})
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "Register")
	}
	refreshToken, rtExp, _, err := a.jwtUtil.GenerateRefreshToken(res)
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "Register")
	}
	now := time.Now()

	return model.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		AccessTTL:    atExp.Sub(now),
		RefreshTTL:   rtExp.Sub(now),
		UserId:       res,
	}, nil
}

func (a *authService) Login(ctx context.Context, dto dto.LoginDTO) (model.TokenPair, error) {
	if err := a.v.Struct(dto); err != nil {
		return model.TokenPair{}, customErrors.NewInvalidArgument(err.Error())
	}

	user, err := a.userRepo.GetUserByEmail(ctx, dto.Email)
	if errors.Is(err, customErrors.ErrNotFound) {
		return model.TokenPair{}, customErrors.ErrInvalidCredentials
	}

	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "Login")
	}

	ok, err := argon2id.ComparePasswordAndHash(dto.Password+a.cfg.PasswordPepper, user.PasswordHash)
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "Login")
	}
	if !ok {
		return model.TokenPair{}, customErrors.ErrInvalidCredentials
	}

	accessToken, atExp, _, err := a.jwtUtil.GenerateAccessToken(user.ID, []string{"user"})
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "Login")
	}

	refreshToken, rtExp, _, err := a.jwtUtil.GenerateRefreshToken(user.ID)
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "Login")
	}

	now := time.Now()

	return model.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		AccessTTL:    atExp.Sub(now),
		RefreshTTL:   rtExp.Sub(now),
		UserId:       user.ID,
	}, nil
}

func (a *authService) TelegramAuth(ctx context.Context, dto dto.TelegramAuthDTO) (model.TokenPair, error) {
	// 1. Базовая проверка
	if dto.TelegramID == 0 && dto.InitData == "" {
		return model.TokenPair{}, customErrors.NewInvalidArgument("missing Telegram ID or init_data")
	}

	// 2. Формируем данные для проверки подписи
	var checkMap map[string]string
	var telegramID int64
	var firstName, lastName, username, photoURL string

	if dto.InitData != "" {
		log.Printf("DEBUG: Processing InitData, length=%d", len(dto.InitData))
		log.Printf("DEBUG: InitData first 200 chars: %.200s", dto.InitData)

		// ЕДИНСТВЕННОЕ место где делаем декодирование!
		// Сначала пробуем парсить как есть
		parsed, err := url.ParseQuery(dto.InitData)
		if err != nil {
			log.Printf("DEBUG: Direct parse failed, trying URL decode: %v", err)
			// Если не получилось - пробуем декодировать
			decoded, decodeErr := url.QueryUnescape(dto.InitData)
			if decodeErr != nil {
				log.Printf("DEBUG: URL decode failed: %v", decodeErr)
				return model.TokenPair{}, customErrors.NewInvalidArgument("invalid init_data format")
			}
			log.Printf("DEBUG: Decoded InitData: %.200s", decoded)

			parsed, err = url.ParseQuery(decoded)
			if err != nil {
				log.Printf("DEBUG: Parse after decode failed: %v", err)
				return model.TokenPair{}, customErrors.NewInvalidArgument("invalid init_data format")
			}
		}

		log.Printf("DEBUG: Successfully parsed InitData, keys: %v", getKeys(parsed))

		// Извлекаем auth_date и hash
		authDateStr := parsed.Get("auth_date")
		hash := parsed.Get("hash")

		if authDateStr == "" || hash == "" {
			log.Printf("DEBUG: Missing auth_date(%s) or hash(%s)", authDateStr, hash)
			return model.TokenPair{}, customErrors.NewInvalidArgument("missing auth_date or hash in init_data")
		}

		authDate, err := strconv.ParseInt(authDateStr, 10, 64)
		if err != nil {
			return model.TokenPair{}, customErrors.NewInvalidArgument("invalid auth_date format")
		}

		// Проверка времени
		if err := validateAuthDate(authDate); err != nil {
			return model.TokenPair{}, err
		}

		// Извлекаем пользовательские данные
		if userJSON := parsed.Get("user"); userJSON != "" {
			log.Printf("DEBUG: Found user JSON: %s", userJSON)
			var userData struct {
				ID           int64  `json:"id"`
				FirstName    string `json:"first_name"`
				LastName     string `json:"last_name"`
				Username     string `json:"username"`
				LanguageCode string `json:"language_code"`
				PhotoURL     string `json:"photo_url"`
			}

			if err := json.Unmarshal([]byte(userJSON), &userData); err != nil {
				log.Printf("DEBUG: Failed to unmarshal user JSON: %v", err)
				return model.TokenPair{}, customErrors.NewInvalidArgument("invalid user data in init_data")
			}

			telegramID = userData.ID
			firstName = userData.FirstName
			lastName = userData.LastName
			username = userData.Username
			photoURL = userData.PhotoURL

			log.Printf("DEBUG: Extracted user data: ID=%d, FirstName=%s, Username=%s",
				telegramID, firstName, username)
		}

		// Формируем checkMap из всех параметров кроме hash и signature
		checkMap = make(map[string]string)
		for key, values := range parsed {
			if (key == "hash" || key == "signature") || len(values) == 0 {
				continue
			}
			checkMap[key] = values[0]
		}

		// Устанавливаем hash для проверки
		dto.Hash = hash

		log.Printf("DEBUG: CheckMap keys: %v", getKeys2(checkMap))

	} else {
		// Используем данные из отдельных полей (для веб-виджета)
		log.Printf("DEBUG: Using web widget data")

		telegramID = dto.TelegramID
		firstName = dto.FirstName
		lastName = dto.LastName
		username = dto.Username
		photoURL = dto.PhotoURL

		// Проверка времени
		if err := validateAuthDate(dto.AuthDate); err != nil {
			return model.TokenPair{}, err
		}

		// Формируем checkMap из переданных полей
		checkMap = map[string]string{
			"auth_date": fmt.Sprintf("%d", dto.AuthDate),
			"id":        fmt.Sprintf("%d", dto.TelegramID),
		}

		if firstName != "" {
			checkMap["first_name"] = firstName
		}
		if lastName != "" {
			checkMap["last_name"] = lastName
		}
		if username != "" {
			checkMap["username"] = username
		}
		if photoURL != "" {
			checkMap["photo_url"] = photoURL
		}
	}

	// 3. Проверяем подпись
	log.Printf("DEBUG: Checking auth with hash: %s, checkMap: %+v", dto.Hash, checkMap)
	valid := false
	if dto.InitData != "" {
		valid = telegram.CheckWebAppAuth(checkMap, dto.Hash, a.cfg.TelegramBotToken)
	} else {
		valid = telegram.CheckAuth(checkMap, dto.Hash, a.cfg.TelegramBotToken)
	}
	if !valid {
		log.Printf("DEBUG: CheckAuth failed!")
		log.Printf("CheckMap: %+v", checkMap)
		log.Printf("Hash: %s", dto.Hash)
		log.Printf("BotToken length: %d", len(a.cfg.TelegramBotToken))
		return model.TokenPair{}, customErrors.ErrInvalidCredentials
	}

	log.Printf("DEBUG: CheckAuth succeeded!")

	// 4. Создание/обновление пользователя
	user, err := a.userRepo.GetUserByTelegramID(ctx, telegramID)
	if err != nil && !errors.Is(err, customErrors.ErrNotFound) {
		return model.TokenPair{}, customErrors.WrapInternal(err, "TelegramAuth")
	}

	if errors.Is(err, customErrors.ErrNotFound) {
		email := fmt.Sprintf("tg%d@telegram.local", telegramID)
		passHash, _ := argon2id.CreateHash(uuid.NewString()+a.cfg.PasswordPepper, argon2id.DefaultParams)
		user = model.User{
			ID:              uuid.New(),
			Email:           email,
			PasswordHash:    passHash,
			Username:        nonEmpty(username, fmt.Sprintf("tg%d", telegramID)),
			TelegramID:      telegramID,
			FirstName:       firstName,
			LastName:        lastName,
			ProfilePhotoURL: photoURL,
		}
		if _, err := a.userRepo.CreateUser(ctx, user); err != nil {
			return model.TokenPair{}, customErrors.WrapInternal(err, "CreateUser")
		}
	} else {
		// Обновляем существующего пользователя
		changed := false
		if username != "" && user.Username != username {
			user.Username = username
			changed = true
		}
		if firstName != "" && user.FirstName != firstName {
			user.FirstName = firstName
			changed = true
		}
		if lastName != "" && user.LastName != lastName {
			user.LastName = lastName
			changed = true
		}
		if photoURL != "" && user.ProfilePhotoURL != photoURL {
			user.ProfilePhotoURL = photoURL
			changed = true
		}
		if changed {
			if err := a.userRepo.UpdateUser(ctx, user); err != nil {
				// Логируем ошибку, но не прерываем процесс
				log.Printf("Warning: failed to update user: %v", err)
			}
		}
	}

	// 5. Генерируем токены
	accessToken, atExp, _, err := a.jwtUtil.GenerateAccessToken(user.ID, []string{"user"})
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "GenerateAccessToken")
	}
	refreshToken, rtExp, _, err := a.jwtUtil.GenerateRefreshToken(user.ID)
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "GenerateRefreshToken")
	}
	nowTime := time.Now()

	return model.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		AccessTTL:    atExp.Sub(nowTime),
		RefreshTTL:   rtExp.Sub(nowTime),
		UserId:       user.ID,
	}, nil
}

// Вспомогательные функции
func validateAuthDate(authDate int64) error {
	now := time.Now().Unix()
	authAge := now - authDate
	if authAge > 86400 { // 24 часа
		return customErrors.NewInvalidArgument("auth_date too old")
	}
	if authAge < -300 { // не более 5 минут в будущем
		return customErrors.NewInvalidArgument("auth_date in future")
	}
	return nil
}

func getKeys(m url.Values) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func getKeys2(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func nonEmpty(s, fallback string) string {
	if s != "" {
		return s
	}
	return fallback
}

func (a *authService) Validate(ctx context.Context, dto dto.ValidateDTO) (model.User, error) {

	if err := a.v.Struct(dto); err != nil {
		return model.User{}, customErrors.NewInvalidArgument(err.Error())
	}

	claims, err := a.jwtUtil.ValidateAccessToken(dto.AccessToken)
	if err != nil {
		return model.User{}, customErrors.ErrInvalidToken
	}

	revoked, err := a.tokenRepo.IsRevoked(ctx, claims.ID)
	if err != nil {
		return model.User{}, customErrors.WrapInternal(err, "Validate")
	}
	if revoked {
		return model.User{}, customErrors.ErrInvalidToken
	}

	uid, err := uuid.Parse(claims.Subject)

	if err != nil {
		return model.User{}, customErrors.ErrInvalidToken
	}
	user, err := a.userRepo.GetUserByID(ctx, uid)

	if err != nil {
		return model.User{}, customErrors.ErrInvalidToken
	}
	return user, nil
}

func (a *authService) Refresh(ctx context.Context, dto dto.RefreshDTO) (model.TokenPair, error) {

	if err := a.v.Struct(dto); err != nil {
		return model.TokenPair{}, customErrors.NewInvalidArgument(err.Error())
	}

	claims, err := a.jwtUtil.ValidateRefreshToken(dto.RefreshToken)
	if err != nil {
		return model.TokenPair{}, customErrors.ErrInvalidToken
	}

	revoked, err := a.tokenRepo.IsRevoked(ctx, claims.ID)
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "Refresh")
	}
	if revoked {
		return model.TokenPair{}, customErrors.ErrInvalidToken
	}

	err = a.tokenRepo.Revoke(ctx, claims.ID, claims.ExpiresAt.Time)
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "Refresh")
	}

	uid, err := uuid.Parse(claims.Subject)
	if err != nil {
		return model.TokenPair{}, customErrors.ErrInvalidToken
	}

	accessToken, atExp, _, err := a.jwtUtil.GenerateAccessToken(uid, []string{"user"})
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "Refresh")
	}

	refreshToken, rtExp, _, err := a.jwtUtil.GenerateRefreshToken(uid)
	if err != nil {
		return model.TokenPair{}, customErrors.WrapInternal(err, "Refresh")
	}

	now := time.Now()

	return model.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		AccessTTL:    atExp.Sub(now),
		RefreshTTL:   rtExp.Sub(now),
		UserId:       uid,
	}, nil
}

func (a *authService) Logout(ctx context.Context, dto dto.LogoutDTO) error {

	if err := a.v.Struct(dto); err != nil {
		return customErrors.NewInvalidArgument(err.Error())
	}

	claims, err := a.jwtUtil.ValidateRefreshToken(dto.RefreshToken)
	if err != nil {
		return customErrors.ErrInvalidToken
	}

	err = a.tokenRepo.Revoke(ctx, claims.ID, claims.ExpiresAt.Time)
	if err != nil {
		return customErrors.WrapInternal(err, "Logout")
	}

	return nil
}
