package logger

import (
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	ctrl "sigs.k8s.io/controller-runtime"
)

type TestLogger struct {
	Logger *zap.Logger
	Logs   *observer.ObservedLogs
}

func New() *TestLogger {
	zobs, logs := observer.New(zapcore.DebugLevel)
	logger := zap.New(zobs)
	ctrl.SetLogger(zapr.NewLogger(logger))
	return &TestLogger{
		Logger: logger,
		Logs:   logs,
	}
}
