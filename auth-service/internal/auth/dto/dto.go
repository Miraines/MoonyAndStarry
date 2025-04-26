package dto

type RegisterDTO struct {
	Email    string `json:"email"    validate:"required,email"`
	Password string `json:"password" validate:"required,min=8,matches=^(?=.*[A-Z])(?=.*\\d).+$"`
	Username string `json:"username" validate:"required,alphanumunderscore,min=3,max=20"`
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
