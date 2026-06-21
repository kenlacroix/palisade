// Package config persists agent enrollment state to disk.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Config is the persisted agent identity written after enrollment.
type Config struct {
	AgentID     string `json:"agent_id"`
	AgentSecret string `json:"agent_secret"`
	Server      string `json:"server"`
}

// Dir returns the palisade home directory, honoring PALISADE_HOME.
func Dir() string {
	if d := os.Getenv("PALISADE_HOME"); d != "" {
		return d
	}
	return ".palisade"
}

func path() string {
	return filepath.Join(Dir(), "config.json")
}

// Load reads config.json. Returns an error if the agent is not enrolled.
func Load() (*Config, error) {
	b, err := os.ReadFile(path())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("not enrolled: %s missing (run `palisade enroll` first)", path())
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if c.AgentID == "" || c.AgentSecret == "" {
		return nil, errors.New("config is incomplete: missing agent_id or agent_secret")
	}
	return &c, nil
}

// Save writes config.json with 0600 perms (it holds the agent secret).
func Save(c *Config) error {
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", Dir(), err)
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(path(), b, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}
