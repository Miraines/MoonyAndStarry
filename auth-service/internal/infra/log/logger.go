package log

import (
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func New(levelEnv string) (*zap.Logger, error) {
	cfg := zap.NewDevelopmentConfig()
	cfg.EncoderConfig.TimeKey = "ts"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel) // default DEBUG

	if levelEnv != "" {
		if err := cfg.Level.UnmarshalText([]byte(levelEnv)); err != nil {
			fmt.Printf("bad LOG_LEVEL=%s, fallback to debug\n", levelEnv)
		}
	}
	return cfg.Build(zap.AddCaller(), zap.AddStacktrace(zap.ErrorLevel))
}

func Must(levelEnv string) *zap.Logger {
	l, err := New(levelEnv)
	if err != nil {
		panic(err)
	}
	return l
}
