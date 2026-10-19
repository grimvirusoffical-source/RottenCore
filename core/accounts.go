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

// StubAccounts is the placeholder until Red-XAI Accounts has an API.
type StubAccounts struct{}

func (StubAccounts) SignIn(context.Context) (*Session, error) { return nil, ErrAccountsComingSoon }
func (StubAccounts) SignOut(context.Context) error            { return nil }
func (StubAccounts) Current() *Session                        { return nil }
