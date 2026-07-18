// Package config provides server configuration for the authlib examples.
// Settings are resolved from environment variables, with fallback to caller-supplied
// defaults or built-in constants when neither is present.
package config

import (
	"os"
	"strconv"
)

const (
	// DefaultIssuerPort is the TCP port the example server listens on when
	// SERVER_PORT is not set.
	DefaultIssuerPort = 9090

	// DefaultAddress is the IP address the example server binds to when
	// SERVER_ADDRESS is not set.
	DefaultAddress = "127.0.0.1"
)

// Config holds the network settings for an example server.
type Config struct {
	// Port is the TCP port to listen on (e.g. "9090").
	Port int

	// Address is the IP address to bind to (e.g. "127.0.0.1").
	Address string
}

// FromEnvVars builds a Config from environment variables, falling back to
// defaults when a variable is absent. If defaults is nil, built-in constants
// are used.
func FromEnvVars(defaults *Config) *Config {
	if defaults == nil {
		defaults = &Config{
			Port:    DefaultIssuerPort,
			Address: DefaultAddress,
		}
	}
	cfg := &Config{
		Port:    defaults.Port,
		Address: defaults.Address,
	}

	if v, ok := os.LookupEnv("SERVER_PORT"); ok {
		if p, err := strconv.Atoi(v); err != nil {
			cfg.Port = p
		}
	}

	if v, ok := os.LookupEnv("SERVER_ADDRESS"); ok {
		cfg.Address = v
	}

	return cfg
}
