// Package config keeps the portals the user trusts. Nothing secret is stored:
// no PIN, no password, no signing link.
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sync"
)

type Config struct {
	// Portals are the origins (https://portal.example.org) whose signing links are accepted.
	Portals []string `json:"portals"`

	path string
	lock sync.Mutex
}

// Load reads the configuration; a missing file is an empty configuration.
func Load(path string) (*Config, error) {
	config := &Config{path: path}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return config, nil
	}
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(data, config); err != nil {
		return nil, err
	}

	return config, nil
}

// DefaultPath is the configuration file in the user's configuration directory.
func DefaultPath() (string, error) {
	directory, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(directory, "eyazisma-imza", "config.json"), nil
}

func (c *Config) Trusts(origin string) bool {
	c.lock.Lock()
	defer c.lock.Unlock()

	return slices.Contains(c.Portals, origin)
}

// Trust remembers a portal.
func (c *Config) Trust(origin string) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	if slices.Contains(c.Portals, origin) {
		return nil
	}

	c.Portals = append(c.Portals, origin)

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}

	return os.WriteFile(c.path, data, 0o600)
}
