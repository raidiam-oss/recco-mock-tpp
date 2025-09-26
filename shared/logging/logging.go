package logging

import (
	"log/slog"
	"os"
)

// InitLogger initializes the logger and sets it as the default
func InitLogger() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))
}
