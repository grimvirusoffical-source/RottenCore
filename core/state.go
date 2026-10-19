package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Entry is one installed app in installed.json.
type Entry struct {
	AppID        string     `json:"appId"`
	Name         string     `json:"name"`
	Version      string     `json:"version"`
	Source       string     `json:"source"` // store | github | unknown
	Trusted      bool       `json:"trusted"`
	TrustedBy    string     `json:"trustedBy,omitempty"`
	AcceptedRisk bool       `json:"acceptedRisk"` // the person accepted the untrusted warning
	Kind         string     `json:"kind"`
	ArtifactName string     `json:"artifactName,omitempty"`
	SHA256       string     `json:"sha256,omitempty"`
	Paths        []string   `json:"paths"`
	PkgIDs       []string   `json:"pkgIds,omitempty"`
	GitHub       *GitHubRef `json:"github,omitempty"`
	Store        *StoreRef  `json:"store,omitempty"`
	AgeRating    string     `json:"ageRating,omitempty"`
	Codesign     *Codesign  `json:"codesign,omitempty"`
	Managed      string     `json:"managed,omitempty"` // "ra-launcher": installed, updated and removed by the Rotten Apple launcher
	// Red-XAI signature (M2): who signed it, the chain's certificate fingerprints (for revocation checks
	// later), whether it was a TEST chain, whether RottenCore removed the quarantine flag, and the current
	// revocation mark ("" = not revoked).
	Signer            *CertSubject `json:"signer,omitempty"`
	CertFPs           []string     `json:"certFingerprints,omitempty"`
	SigTest           bool         `json:"signatureTest,omitempty"`
	QuarantineRemoved bool         `json:"quarantineRemoved,omitempty"`
	Revoked           string       `json:"revoked,omitempty"`
	RevokedAt         time.Time    `json:"revokedAt,omitempty"`
	InstalledAt       time.Time    `json:"installedAt"`
	UpdatedAt         time.Time    `json:"updatedAt"`
}

// State is ~/Library/Application Support/RottenCore/installed.json.
type State struct {
	Dir string
}

type stateFile struct {
	Schema int     `json:"schema"`
	Apps   []Entry `json:"apps"`
}

func (s *State) path() string { return filepath.Join(s.Dir, "installed.json") }

// lock serializes writers across processes with an exclusive lock file (stale after 10 minutes).
func (s *State) lock() (func(), error) {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return nil, err
	}
	p := filepath.Join(s.Dir, "installed.lock")
	for i := 0; i < 100; i++ {
		f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			f.Close()
			return func() { os.Remove(p) }, nil
		}
		if st, e := os.Stat(p); e == nil && time.Since(st.ModTime()) > 10*time.Minute {
			os.Remove(p)
			continue
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil, errors.New("another RottenCore is changing the installed list; try again")
}

// List returns all entries, sorted by name.
func (s *State) List() ([]Entry, error) {
	b, err := os.ReadFile(s.path())
	if errors.Is(err, os.ErrNotExist) {
		return []Entry{}, nil
	}
	if err != nil {
		return nil, err
	}
	var f stateFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("installed.json is damaged: %w", err)
	}
	if f.Apps == nil {
		f.Apps = []Entry{}
	}
	sort.Slice(f.Apps, func(i, j int) bool { return f.Apps[i].Name < f.Apps[j].Name })
	return f.Apps, nil
}

// Get returns one entry or nil.
func (s *State) Get(appID string) (*Entry, error) {
	l, err := s.List()
	if err != nil {
		return nil, err
	}
	for i := range l {
		if l[i].AppID == appID {
			return &l[i], nil
		}
	}
	return nil, nil
}

// Put adds or replaces an entry (the first install time is kept).
func (s *State) Put(e Entry) error {
	return s.mutate(func(l []Entry) []Entry {
		for i := range l {
			if l[i].AppID == e.AppID {
				e.InstalledAt = l[i].InstalledAt
				l[i] = e
				return l
			}
		}
		return append(l, e)
	})
}

// Remove drops an entry.
func (s *State) Remove(appID string) error {
	return s.mutate(func(l []Entry) []Entry {
		out := []Entry{}
		for _, e := range l {
			if e.AppID != appID {
				out = append(out, e)
			}
		}
		return out
	})
}

func (s *State) mutate(fn func([]Entry) []Entry) error {
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	l, err := s.List()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(stateFile{Schema: 1, Apps: fn(l)}, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path())
}
