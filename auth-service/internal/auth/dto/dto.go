package dto

type RegisterDTO struct {
	Email    string `json:"email"    validate:"required,email"`
	Password string `json:"password" validate:"required,strongpwd"`
	Username string `json:"username" validate:"required,alphanum,min=3,max=20"`
}

type LoginDTO struct {
	Email    string `json:"email"    validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type RefreshDTO struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type ValidateDTO struct {
	AccessToken string `json:"access_token" validate:"required"`
}

type LogoutDTO struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// internal/auth/dto/telegram.go
type TelegramAuthDTO struct {
	// ---------- Веб-виджет ----------
	ID        int64  `form:"id"`         // Telegram user id
	FirstName string `form:"first_name"` // имя
	LastName  string `form:"last_name"`  // фамилия (может быть пустым)
	Username  string `form:"username"`   // username
	PhotoURL  string `form:"photo_url"`  // ссылка на фото

	// ---------- Mini App ----------
	User    string `form:"user"`     // JSON-строка с данными пользователя
	QueryID string `form:"query_id"` // идентификатор сессии Mini App

	// Иногда Mini App (Web-App) присылает всё одной строкой initData.
	InitData string `form:"init_data" json:"init_data"` // URL-encoded "auth_date=...&user=...&hash=..."

	// ---------- Общие обязательные ----------
	// ⚠️   НЕ ставим binding:"required" — проверим вручную в хэндлере
	AuthDate int64  `form:"auth_date"` // Unix-timestamp
	Hash     string `form:"hash"`      // HMAC-SHA256 hex

	// ---------- Внутреннее ----------
	TelegramID int64 `form:"-"` // заполняем вручную после парсинга
}
