package authlib

import (
	"log"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger *zap.Logger
var loggerOnce sync.Once

// Get returns the singleton logger instance
func getLogger() *zap.Logger {
	loggerOnce.Do(func() {
		var err error
		logger, err = zap.Config{
			Encoding:    "console",
			Level:       zap.NewAtomicLevelAt(zapcore.DebugLevel),
			OutputPaths: []string{"stdout"},
			EncoderConfig: zapcore.EncoderConfig{
				TimeKey:     "time",
				EncodeTime:  zapcore.RFC3339TimeEncoder,
				LevelKey:    "level",
				EncodeLevel: zapcore.CapitalColorLevelEncoder,
				MessageKey:  "message",
				NameKey:     "name",
				EncodeName:  zapcore.FullNameEncoder,
			},
		}.Build()
		if err != nil {
			log.Fatalln("Error loading logger:", err)
		} else {
			logger = logger.Named("AUTHLIB")
		}
	})
	return logger
}
