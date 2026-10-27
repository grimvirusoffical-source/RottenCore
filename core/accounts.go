package core

import (
	"context"
	"errors"
)

// Accounts is the sign-in hook for Red-XAI Accounts, the shared account system for every Red-XAI app.
// It is still being built; RottenCore v0.1.0 ships only the interface and a stub. Age rules (13 and up)
// are enforced by Red-XAI Accounts and the store, never here.
type Accounts interface {
	// SignIn starts sign-in and returns a session for store reads that need an account.
	SignIn(ctx context.Context) (*Session, error)
	SignOut(ctx context.Context) error
	Current() *Session
}

// Session is a signed-in account as RottenCore sees it. The token stays in memory (the app keeps it in
// the macOS Keychain once sign-in exists).
type Session struct {
	Account   string `json:"account"`
	MaxRating string `json:"maxRating"` // everyone | 13+ | 18+, from the account system
	Token     string `json:"-"`
}

// ErrAccountsComingSoon is what the stub answers.
var ErrAccountsComingSoon = errors.New("Red-XAI Accounts sign-in is coming soon")

// ErrSignInRequired is returned when a command needs an access token and none was given.
var ErrSignInRequired = errors.New("sign in to Red-XAI Accounts first")

// Profile is the rxa-account view RottenCore needs. The access token is not stored here.
type Profile struct {
	Sub               string
	Email             string
	PreferredUsername string
	AgeBand           string
	Verified          bool
	AdultVerified     bool
	IDVerified        bool
	IDVerifiedMs      int64
	MFA               bool
	AMR               []string
	sawID             bool
}

// LifetimeCert is an Accounts document of kind rxa-lifetime-cert.
// PrivateEnc is Red-SecretsXAI ciphertext. Accounts returns it only for an owner session.
// RottenCore decrypts it in memory and does not keep this field after that.
type LifetimeCert struct {
	Kind        string   `json:"kind"`
	CertID      string   `json:"cert_id"`
	PubKey      string   `json:"pubkey"`
	PrivateEnc  string   `json:"private_enc,omitempty"`
	Issued      string   `json:"issued,omitempty"`
	OwnerEmails []string `json:"owner_emails"`
	SigIDPrefix string   `json:"sig_id_prefix"`
}

// StubAccounts is the placeholder until Red-XAI Accounts has an API.
type StubAccounts struct{}

func (StubAccounts) SignIn(context.Context) (*Session, error) { return nil, ErrAccountsComingSoon }
func (StubAccounts) SignOut(context.Context) error            { return nil }
func (StubAccounts) Current() *Session                        { return nil }
