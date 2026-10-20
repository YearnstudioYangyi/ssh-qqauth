package config

import (
	"encoding/json"
	"os"
)

type Config struct {
	EnablePIN         bool   `json:"enable_pin"`
	PIN               string `json:"pin"`
	AuthSocket        string `json:"auth_socket"`
	BotSocket         string `json:"bot_socket"`
	BanDurationMin    int    `json:"ban_duration_minutes"`
	MaxFailedAttempts int    `json:"max_failed_attempts"`
	RateWindowSeconds int    `json:"rate_window_seconds"`
}

func DefaultConfig() *Config {
	return &Config{
		EnablePIN:         true,
		PIN:               "123456",
		AuthSocket:        "/run/qqauthd/auth.sock",
		BotSocket:         "/run/qqauthd/botipc.sock",
		BanDurationMin:    30,
		MaxFailedAttempts: 3,
		RateWindowSeconds: 60,
	}
}

// LoadConfig 从指定路径加载配置，若路径为空或文件不存在则使用默认配置
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	if path == "" {
		// 优先尝试 /etc/qqauth/config.json，再尝试本地相对路径
		for _, candidate := range []string{"/etc/qqauth/config.json", "config.json"} {
			if _, err := os.Stat(candidate); err == nil {
				path = candidate
				break
			}
		}
	}

	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}
