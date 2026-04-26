package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	DatabaseURL        string
	TTLockClientID     string
	TTLockClientSecret string
	TTLockBaseURL      string
	TTLockUsername     string
	TTLockPasswordMD5  string
}

// Load reads environment variables, optionally seeding them from a .env file.
func Load(envFile string) (Config, error) {
	if envFile != "" {
		_ = loadDotEnv(envFile)
	}

	cfg := Config{
		DatabaseURL:        strings.TrimSpace(os.Getenv("DATABASE_URL")),
		TTLockClientID:     strings.TrimSpace(os.Getenv("TTLOCK_CLIENT_ID")),
		TTLockClientSecret: strings.TrimSpace(os.Getenv("TTLOCK_CLIENT_SECRET")),
		TTLockBaseURL:      strings.TrimSpace(os.Getenv("TTLOCK_BASE_URL")),
		TTLockUsername:     strings.TrimSpace(os.Getenv("TTLOCK_USERNAME")),
		TTLockPasswordMD5:  strings.TrimSpace(os.Getenv("TTLOCK_PASSWORD_MD5")),
	}

	if cfg.TTLockBaseURL == "" {
		cfg.TTLockBaseURL = "https://api.ttlock.com"
	}

	if cfg.DatabaseURL == "" {
		return Config{}, errors.New("DATABASE_URL is required")
	}

	return cfg, nil
}

func loadDotEnv(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open env file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if key != "" {
			_ = os.Setenv(key, val)
		}
	}

	return scanner.Err()
}
