package uploader

import (
	"context"
	"errors"
	"fmt"

	"github.com/grimvirusoffical-source/RottenCore/core"
	"github.com/grimvirusoffical-source/RottenCore/devhub"
)

// QAStatus is a QA sign-off decision for an app version.
type QAStatus struct {
	App       string `json:"app"`
	Version   string `json:"version"`
	SignedOff bool   `json:"signedOff"`
	By        string `json:"by,omitempty"`
	Note      string `json:"note,omitempty"`
}

// QAGate reports whether a version has QA sign-off. Publishing is blocked until it does. The mechanism (a
// signed sign-off document from a QA identity, a release-PR label, ...) is still open; this interface lets
// the uploader gate publishing without deciding it.
type QAGate interface {
	SignedOff(ctx context.Context, app, version string) (QAStatus, error)
}

// ErrQANotSignedOff blocks a publish.
var ErrQANotSignedOff = errors.New("publishing is blocked until QA signs off on this version")

// Publisher publishes an already-uploaded version to a store adapter, after the QA gate passes.
type Publisher struct {
	QA  QAGate
	Ctx *devhub.BuildContext
}

// PublishTarget is a store that can publish a release (e.g. a Red-XAI Host / GitHub via HostClient).
type PublishTarget interface {
	PublishRelease(ctx context.Context, app string, req core.PublishRequest) error
	Name() string
}

// Publish checks the build API key and the QA gate, then publishes through the target. It never publishes a
// version QA has not signed off.
func (p *Publisher) Publish(ctx context.Context, target PublishTarget, app, version string, req core.PublishRequest) error {
	if err := p.Ctx.RequireBuildKey(); err != nil {
		return err
	}
	if p.QA == nil {
		return ErrQANotSignedOff
	}
	st, err := p.QA.SignedOff(ctx, app, version)
	if err != nil {
		return err
	}
	if !st.SignedOff {
		return fmt.Errorf("%w (%s %s)", ErrQANotSignedOff, app, version)
	}
	return target.PublishRelease(ctx, app, req)
}

// HostPublishStore adapts core.HostClient.Publish (Red-XAI Host / GitHub release) to PublishTarget. Hosted,
// AllowOwner and AllowRepo are the host's allowlist for this app (asset URLs are checked against them).
type HostPublishStore struct {
	Host       *core.HostClient
	Hosted     bool
	AllowOwner string
	AllowRepo  string
}

func (h *HostPublishStore) Name() string { return "Red-XAI Host / GitHub" }

func (h *HostPublishStore) PublishRelease(ctx context.Context, app string, req core.PublishRequest) error {
	_, err := h.Host.Publish(ctx, app, h.Hosted, h.AllowOwner, h.AllowRepo, req)
	return err
}
