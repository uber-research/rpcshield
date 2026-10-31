// Package common holds cmd/rpcshield helpers with no monorepo-internal dependencies.
// Monorepo-only helpers (SSO auth, telemetry, CI
// CI signals) live in cmd/rpcshield/uberutil instead.
package common

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// BuildLogger builds a zap logger with the given log level, and only shows stacktraces at Error level.
func BuildLogger(level zapcore.Level) (*zap.SugaredLogger, error) {
	logConfig := zap.NewDevelopmentConfig()
	logConfig.Level.SetLevel(level)
	logger, err := logConfig.Build(zap.AddStacktrace(zap.ErrorLevel))
	if err != nil {
		return nil, err
	}

	return logger.Sugar(), nil
}
