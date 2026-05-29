package config

import "os"

type Config struct {
	Addr      string
	DBPath    string
	JWTSecret string
}

func Load() Config {
	return Config{
		Addr:      getEnv("APP_ADDR", ":8080"),
		DBPath:    getEnv("DB_PATH", "./data/transport.db"),
		JWTSecret: getEnv("JWT_SECRET", "dev-secret-change-me"),
	}
}

func getEnv(key string, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	return value
}
