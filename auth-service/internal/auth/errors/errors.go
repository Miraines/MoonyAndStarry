package errors

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidArgument    = errors.New("invalid argument")
	ErrInternal           = errors.New("internal error")
	ErrNotFound           = errors.New("not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAlreadyExists      = errors.New("already exists")
	ErrInvalidToken       = errors.New("invalid token")
	ErrInvalidPassword    = errors.New("invalid password")
	ErrInvalidUsername    = errors.New("invalid username")
)

func NewInvalidArgument(msg string) error {
	return fmt.Errorf("%w: %s", ErrInvalidArgument, msg)
}

func WrapInternal(err error, context string) error {
	return fmt.Errorf("%w: %s: %v", ErrInternal, context, err)
}

func IsInvalidArgument(err error) bool {
	return errors.Is(err, ErrInvalidArgument)
}

func IsInternal(err error) bool {
	return errors.Is(err, ErrInternal)
}

func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

func IsInvalidCredentials(err error) bool {
	return errors.Is(err, ErrInvalidCredentials)
}

func IsAlreadyExists(err error) bool {
	return errors.Is(err, ErrAlreadyExists)
}

func IsInvalidToken(err error) bool {
	return errors.Is(err, ErrInvalidToken)
}

func IsInvalidPassword(err error) bool {
	return errors.Is(err, ErrInvalidPassword)
}

func IsInvalidUsername(err error) bool {
	return errors.Is(err, ErrInvalidUsername)
}
