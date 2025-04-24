package dto

type RegisterDTO struct {
	Email    string
	Password string
	Username string
}

type LoginDTO struct {
	Email    string
	Password string
}

type RefreshDTO struct {
	RefreshToken string
}

type ValidateDTO struct {
	AccessToken string
}

type LogoutDTO struct {
	RefreshToken string
}
