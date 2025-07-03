package model

import (
	"github.com/google/uuid"
	"time"
)

type User struct {
	ID              uuid.UUID
	Email           string
	PasswordHash    string
	Username        string
	TelegramID      int64
	FirstName       string
	LastName        string
	ProfilePhotoURL string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type TokenPair struct {
	AccessToken     string
	RefreshToken    string
	AccessTTL       time.Duration
	RefreshTTL      time.Duration
	UserId          uuid.UUID
	RefreshTokenJTI string
}
