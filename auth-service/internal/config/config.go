package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	DatabaseURL       string
	JWTPrivateKeyPath string
	JWTPublicKeyPath  string
	AccessTokenTTL    time.Duration
	RefreshTokenTTL   time.Duration
	RedisAddress      string
	RedisPassword     string
	RedisDB           int
	PasswordPepper    string
	Issuer            string
	Audience          string
	GRPCAddress       string
	TelegramBotToken  string
	HTTPSCertFile     string
	HTTPSKeyFile      string
	AllowedOrigins    []string
	AllowCredentials  bool
}

func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("json")
	viper.AddConfigPath(".")

	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	for _, key := range []string{
		"DATABASE_URL",
		"JWT_PRIVATE_KEY_PATH",
		"JWT_PUBLIC_KEY_PATH",
		"ACCESS_TOKEN_TTL",
		"REFRESH_TOKEN_TTL",
		"REDIS_ADDRESS",
		"REDIS_PASSWORD",
		"REDIS_DB",
		"ALLOWED_ORIGINS",
		"ALLOW_CREDENTIALS",
		"PASSWORD_PEPPER",
		"JWT_ISSUER",
		"JWT_AUDIENCE",
		"GRPC_ADDRESS",
		"TELEGRAM_BOT_TOKEN",
	} {
		if err := viper.BindEnv(key); err != nil {
			return nil, fmt.Errorf("bind env %s: %w", key, err)
		}
	}

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	cfg := &Config{
		DatabaseURL:       viper.GetString("DATABASE_URL"),
		JWTPrivateKeyPath: viper.GetString("JWT_PRIVATE_KEY_PATH"),
		JWTPublicKeyPath:  viper.GetString("JWT_PUBLIC_KEY_PATH"),
		AccessTokenTTL:    viper.GetDuration("ACCESS_TOKEN_TTL"),
		RefreshTokenTTL:   viper.GetDuration("REFRESH_TOKEN_TTL"),
		RedisAddress:      viper.GetString("REDIS_ADDRESS"),
		RedisPassword:     viper.GetString("REDIS_PASSWORD"),
		RedisDB:           viper.GetInt("REDIS_DB"),
		PasswordPepper:    viper.GetString("PASSWORD_PEPPER"),
		Issuer:            viper.GetString("JWT_ISSUER"),
		Audience:          viper.GetString("JWT_AUDIENCE"),
		GRPCAddress:       viper.GetString("GRPC_ADDRESS"),
		TelegramBotToken:  viper.GetString("TELEGRAM_BOT_TOKEN"),
		AllowedOrigins:    viper.GetStringSlice("ALLOWED_ORIGINS"),
		AllowCredentials:  viper.GetBool("ALLOW_CREDENTIALS"),
		HTTPSCertFile:     viper.GetString("HTTPS_CERT_FILE"),
		HTTPSKeyFile:      viper.GetString("HTTPS_KEY_FILE"),
	}

	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL не задана")
	}
	if cfg.JWTPrivateKeyPath == "" {
		return nil, fmt.Errorf("JWT_PRIVATE_KEY_PATH не задана")
	}
	if cfg.JWTPublicKeyPath == "" {
		return nil, fmt.Errorf("JWT_PUBLIC_KEY_PATH не задана")
	}
	if cfg.AccessTokenTTL <= 0 {
		return nil, fmt.Errorf("ACCESS_TOKEN_TTL не задан или некорректна")
	}
	if cfg.RefreshTokenTTL <= 0 {
		return nil, fmt.Errorf("REFRESH_TOKEN_TTL не задан или некорректна")
	}
	if cfg.RedisAddress == "" {
		return nil, fmt.Errorf("REDIS_ADDRESS не задан")
	}
	if cfg.PasswordPepper == "" {
		return nil, fmt.Errorf("PASSWORD_PEPPER не задан")
	}
	if cfg.GRPCAddress == "" {
		return nil, fmt.Errorf("GRPC_ADDRESS не задан")
	}
	if cfg.TelegramBotToken == "" {
		return nil, fmt.Errorf("TELEGRAM_BOT_TOKEN не задан")
	}

	return cfg, nil
}
