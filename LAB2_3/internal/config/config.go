package config

import "os"

const (
	defaultHost         = "0.0.0.0"
	defaultPort         = "8080"
	defaultDatabasePath = "./transport.db"
	defaultJWTSecret    = "very-secret-key"
)

// Config contains the basic application settings.

type Config struct {
	Host         string
	Port         string
	DatabasePath string
	JWTSecret    string
}

func Load() Config {
	host := getEnv("APP_HOST", defaultHost)
	port := getEnv("APP_PORT", defaultPort)
	databasePath := getEnv("APP_DATABASE_PATH", defaultDatabasePath)
	jwtSecret := getEnv("APP_JWT_SECRET", defaultJWTSecret)

	return Config{
		Host:         host,
		Port:         port,
		DatabasePath: databasePath,
		JWTSecret:    jwtSecret,
	}
}

func (c Config) HTTPAddress() string {
	return c.Host + ":" + c.Port
}

func getEnv(key string, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	return value
}
