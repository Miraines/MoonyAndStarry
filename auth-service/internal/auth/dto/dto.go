package dto

type RegisterDTO struct {
	Email    string `validate:"required,email"`
	Password string `validate:"required,min=8,matches=^(?=.*[A-Z])(?=.*\\d).+$"`
	Username string `validate:"required,alphanum,min=3,max=20"`
}

type LoginDTO struct {
	Email    string `validate:"required,email"`
	Password string `validate:"required"`
}

type RefreshDTO struct {
	RefreshToken string `validate:"required"`
}

type ValidateDTO struct {
	AccessToken string `validate:"required"`
}

type LogoutDTO struct {
	RefreshToken string `validate:"required"`
}
