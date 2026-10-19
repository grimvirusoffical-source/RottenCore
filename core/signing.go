package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// M2: Red-XAI signatures in the install flow (docs/SIGNING.md).
//
// A file's signature is the sidecar <file>.rasig: next to the download, or the release asset of the same
// name on the GitHub release the file came from. (A signature over a file's bytes cannot live inside that
// file; signing an app bundle's contents in place needs a payload tree hash and is planned separately.)
//
// valid (chain + signature + bytes + revocation fresh/in grace) -> trusted: "Signed by <developer>" prompt
// unverifiable / none / invalid                                -> the untrusted warning, explicit accept
// revoked, or a verified signature for other bytes             -> hard refusal

// TrustedByDeveloper / TrustedByDeveloperTest name the trust source on a verdict.
const (
	TrustedByDeveloper     = "red-xai-developer"
	TrustedByDeveloperTest = "red-xai-developer-test"
)

// QuarantineLogName is the audit log of quarantine removals (JSON lines, 0600).
const QuarantineLogName = "quarantine.log"

// revocation returns the revocation state, refreshing the list from the store at most once per Core.
func (c *Core) revocation(ctx context.Context) *RevocationState {
	if c.Rev == nil {
		return nil
	}
	if c.revState != nil {
		return c.revState
	}
	st := c.Rev.Load()
	if c.StoreURL != "" {
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		if s, err := c.Rev.Refresh(rctx, c.Net, strings.TrimRight(c.StoreURL, "/")); err == nil {
			st = s
		} else {
			c.revErr = err
		}
		cancel()
	}
	c.revState = st
	return st
}

func (c *Core) chainPolicy() ChainPolicy {
	return ChainPolicy{Roots: c.Roots, Production: c.Production, Now: c.now()}
}

// applySignature checks the file's Red-XAI signature and merges the result into the verdict.
func (c *Core) applySignature(ctx context.Context, in *Inspection, sum string, size int64) {
	v := in.Verdict
	if in.Kind == KindApp || in.Kind == KindRARXAI {
		return // a bare .app has no single checksum; .rarxai carries its own chain (Poison Apple checks it)
	}
	if in.sigBytes == nil {
		in.sigBytes = readSmall(in.Path + SignatureSidecar)
		if in.sigBytes != nil {
			in.DetectedBy = append(in.DetectedBy, "signature:sidecar")
		}
	}
	var sig *FileSignature
	if in.sigBytes != nil {
		s, err := ParseFileSignature(in.sigBytes)
		if err != nil {
			in.Problems = append(in.Problems, err.Error())
		} else {
			sig = s
		}
	}
	rev := c.revocation(ctx)
	r := VerifyFileSignature(sig, sum, size, c.chainPolicy(), rev)
	if c.revErr != nil && sig != nil {
		r.Reasons = append(r.Reasons, "the revocation list was not refreshed ("+c.revErr.Error()+")")
	}
	in.Signature = r
	switch {
	case r.Refuse() || r.Mismatch:
		v.Refuse, v.Trusted, v.TrustedBy, v.Checksum = true, false, "", "mismatch"
		v.Reasons = append(v.Reasons, r.Reasons...)
	case r.Trusted() && v.Refuse:
		v.Reasons = append(v.Reasons, r.Reasons...)
	case r.Trusted() && in.Manifest != nil && in.Manifest.AppID != r.AppID:
		v.Reasons = append(v.Reasons, fmt.Sprintf("the signature is for %s, the app says it is %s", r.AppID, in.Manifest.AppID))
	case r.Trusted():
		v.Trusted, v.TrustedBy, v.Warning = true, TrustedByDeveloper, ""
		if r.Test {
			v.TrustedBy = TrustedByDeveloperTest
			r.Reasons = append(r.Reasons, "TEST certificate: only trusted because RottenCore was started with a test CA root")
		}
		if v.Checksum == "none" {
			v.Checksum = "match"
			v.Expected = append(v.Expected, Expected{From: "signature", SHA256: sum, Bytes: size})
			kept := v.Reasons[:0]
			for _, x := range v.Reasons {
				if !strings.HasPrefix(x, "no checksum is published") {
					kept = append(kept, x)
				}
			}
			v.Reasons = kept
		}
		v.Reasons = append(v.Reasons, r.Reasons...)
	case sig != nil:
		v.Reasons = append(v.Reasons, r.Reasons...)
	}
	if !v.Trusted && !v.Refuse {
		v.Warning = UntrustedWarning
	}
	if in.AppID == "" && r.AppID != "" && r.Trusted() {
		in.AppID, in.Version = r.AppID, r.Version
	}
}

// QuarantineEligible says whether RottenCore may remove com.apple.quarantine from the installed copy:
// only when the Red-XAI signature is valid under the production chain (not a test CA), the revocation
// check passed on a fresh or in-grace list, and nothing about the file was refused.
func QuarantineEligible(in *Inspection) (bool, string) {
	r := in.Signature
	switch {
	case in.Verdict == nil || in.Verdict.Refuse:
		return false, "the file was refused"
	case r == nil || r.Status != SigValid:
		return false, "no valid Red-XAI signature"
	case r.Test:
		return false, "signed under the TEST CA"
	case r.Revocation != "fresh" && r.Revocation != "grace":
		return false, "the revocation check did not pass"
	case in.Verdict.TrustedBy != TrustedByDeveloper:
		return false, "not trusted by its Red-XAI signature"
	}
	return true, ""
}

type quarantineLog struct {
	At         time.Time `json:"at"`
	AppID      string    `json:"appId"`
	Version    string    `json:"version"`
	Path       string    `json:"path"`
	SHA256     string    `json:"sha256"`
	Signer     string    `json:"signer"`
	Team       string    `json:"team"`
	LeafCert   string    `json:"leafCert"`
	Revocation string    `json:"revocation"`
	Result     string    `json:"result"` // removed | failed: ... | skipped: ...
}

// clearQuarantine removes the quarantine flag from the installed copy of an eligible app and logs every
// decision (removed, failed or skipped) to quarantine.log.
func (c *Core) clearQuarantine(ctx context.Context, in *Inspection, e *Entry) {
	ok, why := QuarantineEligible(in)
	// re-check revocation right before acting
	if ok {
		if reason, state := CheckRevocation(c.revocation(ctx), in.Signature.AppID, "sha256:"+in.Verdict.SHA256, in.Signature.CertFPs, c.now()); reason != "" || (state != "fresh" && state != "grace") {
			ok, why = false, "the revocation check did not pass at install time"
		}
	}
	for _, p := range e.Paths {
		rec := quarantineLog{At: c.now().UTC(), AppID: e.AppID, Version: e.Version, Path: p, SHA256: in.Verdict.SHA256}
		if r := in.Signature; r != nil {
			rec.Revocation = r.Revocation
			if r.Signer != nil {
				rec.Signer, rec.Team = r.Signer.Name, r.Signer.TeamID
			}
			if len(r.CertFPs) > 0 {
				rec.LeafCert = r.CertFPs[0]
			}
		}
		switch {
		case !ok:
			rec.Result = "skipped: " + why
		default:
			if _, err := c.Engine.R.Run(ctx, "/usr/bin/xattr", "-dr", "com.apple.quarantine", p); err != nil {
				rec.Result = "failed: " + err.Error()
			} else {
				rec.Result = "removed"
				e.QuarantineRemoved = true
			}
		}
		c.logQuarantine(rec)
	}
}

func (c *Core) logQuarantine(rec quarantineLog) {
	if c.State == nil {
		return
	}
	_ = os.MkdirAll(c.State.Dir, 0o700)
	f, err := os.OpenFile(filepath.Join(c.State.Dir, QuarantineLogName), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	b, _ := json.Marshal(rec)
	f.Write(append(b, '\n'))
}

// CheckInstalledRevocations refreshes the revocation list and marks installed apps whose app id, build or
// signing certificate is revoked. It returns the updated list.
func (c *Core) CheckInstalledRevocations(ctx context.Context) ([]Entry, string, error) {
	rev := c.revocation(ctx)
	state := rev.Freshness(c.now())
	list, err := c.State.List()
	if err != nil {
		return nil, state, err
	}
	for i := range list {
		e := &list[i]
		build := ""
		if e.SHA256 != "" {
			build = "sha256:" + e.SHA256
		}
		reason, _ := CheckRevocation(rev, e.AppID, build, e.CertFPs, c.now())
		if reason != e.Revoked {
			e.Revoked = reason
			if reason != "" {
				e.RevokedAt = c.now().UTC()
			} else {
				e.RevokedAt = time.Time{}
			}
			if err := c.State.Put(*e); err != nil {
				return nil, state, err
			}
		}
	}
	return list, state, nil
}
