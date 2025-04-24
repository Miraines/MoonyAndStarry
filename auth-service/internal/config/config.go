package config

import (
	"fmt"

	"github.com/spf13/viper"
)

type Config struct {
	DataBaseUrl string
}

func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("json")
	viper.AddConfigPath(".")

	viper.AutomaticEnv()
	err := viper.BindEnv("DATABASE_URL")
	if err != nil {
		return nil, err
	}

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("Error reading config file, %w", err)
		}
	}

	dbURL := viper.GetString("DATABASE_URL")
	if dbURL == "" {
		return nil, fmt.Errorf("DATABASE_URL не задана")
	}

	return &Config{dbURL}, nil
}
