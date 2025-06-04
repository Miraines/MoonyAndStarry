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
	ID        int64  `form:"id"         json:"id"         validate:"required"`
	FirstName string `form:"first_name" json:"first_name"`
	LastName  string `form:"last_name"  json:"last_name"`
	Username  string `form:"username"   json:"username"`
	PhotoURL  string `form:"photo_url"  json:"photo_url"`
	AuthDate  int64  `form:"auth_date"  json:"auth_date"  validate:"required"`
	Hash      string `form:"hash"       json:"hash"       validate:"required"`
}
