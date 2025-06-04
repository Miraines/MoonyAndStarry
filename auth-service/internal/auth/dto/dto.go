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

type TelegramAuthDTO struct {
	ID        int64  `form:"id"`
	FirstName string `form:"first_name"`
	LastName  string `form:"last_name"`
	Username  string `form:"username"`
	PhotoURL  string `form:"photo_url"`

	User    string `form:"user"`
	QueryID string `form:"query_id"`

	InitData string `form:"init_data" json:"init_data"`

	AuthDate int64  `form:"auth_date"`
	Hash     string `form:"hash"`

	TelegramID  int64
	RawWebQuery string
}
