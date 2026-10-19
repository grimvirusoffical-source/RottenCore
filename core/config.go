package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Config is ~/Library/Application Support/RottenCore/config.json. It holds no secrets and cannot add
// trusted keys: store trust comes only from PinnedStoreKeys.
type Config struct {
	StoreURL  string `json:"storeURL,omitempty"`  // Rotten Apple store origin (https)
	GitHubAPI string `json:"githubAPI,omitempty"` // default https://api.github.com
	Theme     string `json:"theme,omitempty"`     // dark (default) | light | system: read by the app
	// AccountsIssuer is the Red-XAI Accounts OIDC issuer; empty = sign-in "coming soon".
	AccountsIssuer   string `json:"accountsIssuer,omitempty"`
	AccountsClientID string `json:"accountsClientId,omitempty"` // default rottencore
}

// DefaultStoreURL is the planned Rotten Apple store API (not live yet).
const DefaultStoreURL = "https://api.rottenapplestore.org"

// SupportDir is where RottenCore keeps its files.
func SupportDir() string {
	if d := os.Getenv("ROTTENCORE_HOME"); d != "" {
		return d
	}
	h, _ := os.UserHomeDir()
	if runtime.GOOS == "darwin" {
		return filepath.Join(h, "Library", "Application Support", "RottenCore")
	}
	return filepath.Join(h, ".local", "share", "rottencore")
}

// LoadConfig reads config.json; ROTTENCORE_STORE_URL overrides the store origin.
func LoadConfig(dir string) (*Config, error) {
	c := &Config{}
	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		if err := json.Unmarshal(b, c); err != nil {
			return nil, fmt.Errorf("config.json: %w", err)
		}
	}
	if c.StoreURL == "" {
		c.StoreURL = DefaultStoreURL
	}
	if v := os.Getenv("ROTTENCORE_STORE_URL"); v != "" {
		c.StoreURL = v
	}
	if c.StoreURL != "" && !ValidOrigin(c.StoreURL, false) {
		return nil, fmt.Errorf("storeURL %q must be an https origin", c.StoreURL)
	}
	if c.AccountsIssuer != "" && !ValidOrigin(c.AccountsIssuer, false) {
		return nil, fmt.Errorf("accountsIssuer %q must be an https origin", c.AccountsIssuer)
	}
	if c.GitHubAPI != "" && !ValidOrigin(c.GitHubAPI, false) {
		return nil, fmt.Errorf("githubAPI %q must be an https origin", c.GitHubAPI)
	}
	return c, nil
}

// SaveConfig writes config.json.
func SaveConfig(dir string, c *Config) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(filepath.Join(dir, "config.json"), b, 0o600)
}

// HostArch is this machine's chip in Apple's spelling.
func HostArch() string {
	if runtime.GOARCH == "amd64" {
		return "x86_64"
	}
	return runtime.GOARCH
}

// NewCore builds the production Core for a support folder.
func NewCore(dir string, admin string) (*Core, error) {
	cfg, err := LoadConfig(dir)
	if err != nil {
		return nil, err
	}
	home, _ := os.UserHomeDir()
	self, _ := os.Executable()
	n := &Net{GitHubAPI: cfg.GitHubAPI, GitHubToken: os.Getenv("ROTTENCORE_GITHUB_TOKEN")}
	return &Core{
		Accounts:   &OIDCAccounts{Issuer: cfg.AccountsIssuer, ClientID: cfg.AccountsClientID, Net: n},
		Net:        n,
		Engine:     &Engine{R: &ExecRunner{Admin: admin}, Applications: "/Applications", UserApps: filepath.Join(home, "Applications"), Home: home},
		State:      &State{Dir: dir},
		StoreURL:   cfg.StoreURL,
		Pins:       PinnedStoreKeys,
		Roots:      PinnedCARoots,
		Production: true,
		Rev:        &RevocationCache{Path: filepath.Join(dir, "status-ticket.json"), Pins: PinnedStoreKeys},
		TmpDir:     filepath.Join(dir, "tmp"),
		SelfPath:   self,
		Arch:       HostArch(),
	}, nil
}
