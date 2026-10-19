package core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Core ties the pieces together. NewCore (config.go) builds the production one.
type Core struct {
	Net      *Net
	Engine   *Engine
	State    *State
	StoreURL string              // default store origin (config)
	Pins     []ed25519.PublicKey // store attestation keys; production = PinnedStoreKeys
	TmpDir   string
	SelfPath string // this rottencore binary, for the root-only pkg-remove step
	Arch     string // arm64 | x86_64
	Now      func() time.Time
	Accounts Accounts
}

// Errors the app shows by name.
var (
	ErrUntrusted    = errors.New(UntrustedWarning + " Accept the warning to install it anyway.")
	ErrRefused      = errors.New("the file's checksum does not match; it was changed or damaged and will not be installed")
	ErrNotInstalled = errors.New("RottenCore did not install this app")
)

func randSuffix() string {
	var b [3]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (c *Core) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Inspection is everything RottenCore found out about a file before installing it. The app shows it.
type Inspection struct {
	Path        string     `json:"path"`
	Kind        string     `json:"kind"`
	AppID       string     `json:"appId"`
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	Source      string     `json:"source"`     // store | github | unknown (what the evidence says; trust is separate)
	DetectedBy  []string   `json:"detectedBy"` // manifest:embedded:app, manifest:sidecar, whereFroms, quarantine, extension, hint
	Manifest    *Manifest  `json:"manifest,omitempty"`
	GitHub      *GitHubRef `json:"github,omitempty"`
	ReleaseURL  string     `json:"releaseUrl,omitempty"`
	Store       *StoreRef  `json:"store,omitempty"`
	Listing     *Listing   `json:"listing,omitempty"`
	AgeRating   string     `json:"ageRating,omitempty"`
	MinMacOS    string     `json:"minMacOS,omitempty"`
	Verdict     *Verdict   `json:"verdict"`
	Problems    []string   `json:"problems"`
	DownloadURL string     `json:"downloadUrl,omitempty"`

	att     *Signed
	mount   string
	cleanup []func()
}

// Close releases a mounted disk image and temporary files.
func (in *Inspection) Close() {
	for i := len(in.cleanup) - 1; i >= 0; i-- {
		in.cleanup[i]()
	}
	in.cleanup = nil
}

// Hint is what the caller already knows (an update or a github: install knows the release).
type Hint struct {
	GitHub *GitHubRef
}

// Inspect detects the source of a file, reads its manifest and checks its bytes. Nothing is installed.
// The caller must Close the result.
func (c *Core) Inspect(ctx context.Context, path string, hint *Hint) (*Inspection, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	in := &Inspection{Path: abs, Kind: KindOf(abs), DetectedBy: []string{}, Problems: []string{}}
	if in.Kind == "" {
		return nil, fmt.Errorf("%s is not an .app, .dmg, .pkg, .zip or .rarxai", filepath.Base(abs))
	}
	if (in.Kind == KindApp) != st.IsDir() {
		return nil, fmt.Errorf("%s does not look like a %s", filepath.Base(abs), in.Kind)
	}
	if err := os.MkdirAll(c.TmpDir, 0o700); err != nil {
		return nil, err
	}
	sum, size := "", int64(0)
	if !st.IsDir() {
		if sum, size, err = FileSHA256(abs); err != nil {
			return nil, err
		}
	}
	// 1. the manifest and attestation: embedded first (it travels inside the bytes), then a sidecar
	var emb, side *found
	switch in.Kind {
	case KindApp:
		emb = fromDir(abs, "embedded:app")
	case KindZIP:
		emb = fromZip(abs)
	case KindPKG:
		emb = fromPkg(ctx, c.Engine.R, abs, c.TmpDir)
	case KindDMG:
		mp, detach, err := c.Engine.Mount(ctx, abs, c.TmpDir)
		if err != nil {
			in.Problems = append(in.Problems, err.Error())
		} else {
			in.mount = mp
			in.cleanup = append(in.cleanup, detach)
			emb = fromDir(mp, "embedded:dmg")
			if emb == nil || emb.manifest == nil {
				if p, k, err := FindPayload(mp, nil); err == nil && k == KindApp {
					if e2 := fromDir(p, "embedded:dmg-app"); e2 != nil {
						emb = e2
					}
				}
			}
		}
	}
	side = &found{where: "sidecar", manifest: readSmall(abs + "." + strings.TrimSuffix(ManifestName, ".json") + ".json"),
		attestation: readSmall(abs + ".rottencore-attestation.json")}
	var mfBytes, attBytes []byte
	var mfWhere string
	if emb != nil && emb.manifest != nil {
		mfBytes, mfWhere = emb.manifest, "manifest:"+emb.where
	} else if side.manifest != nil {
		mfBytes, mfWhere = side.manifest, "manifest:sidecar"
	}
	if emb != nil && emb.attestation != nil {
		attBytes = emb.attestation
	} else if side.attestation != nil {
		attBytes = side.attestation
	}
	if mfBytes != nil {
		m, err := ParseManifest(mfBytes)
		if err != nil {
			in.Problems = append(in.Problems, err.Error())
		} else {
			in.Manifest = m
			in.DetectedBy = append(in.DetectedBy, mfWhere)
			if emb != nil && emb.manifest != nil && side.manifest != nil {
				if sm, err := ParseManifest(side.manifest); err == nil && sm.AppID != m.AppID {
					in.Problems = append(in.Problems, "the sidecar rottencore.json names a different app; the embedded one is used")
				} else if err == nil && sm.Artifact != nil && sm.Artifact.SHA256 != "" {
					m.Artifact = sm.Artifact // only a sidecar can carry the file's own sha256
				}
			}
		}
	}
	if attBytes != nil {
		if s, err := ParseSigned(attBytes); err != nil {
			in.Problems = append(in.Problems, err.Error())
		} else {
			in.att = s
		}
	}
	// 2. fallback signals: where the browser saved it from, the quarantine flag, the extension
	var urls []string
	if hint == nil || hint.GitHub == nil {
		urls = whereFroms(ctx, c.Engine.R, abs)
	}
	if agent, ok := quarantineAgent(ctx, c.Engine.R, abs); ok {
		in.DetectedBy = append(in.DetectedBy, "quarantine:"+agent)
	}
	var urlGH *GitHubRef
	urlStore, urlListing := "", int64(0)
	for _, u := range urls {
		if g, ok := githubFromURL(u); ok && urlGH == nil {
			urlGH, in.DownloadURL = g, u
		}
		if o, id, ok := listingFromURL(u); ok && urlListing == 0 {
			urlStore, urlListing, in.DownloadURL = o, id, u
		}
	}
	if hint != nil && hint.GitHub != nil {
		urlGH = hint.GitHub
		in.DetectedBy = append(in.DetectedBy, "hint:github-release")
	}
	switch {
	case in.Manifest != nil:
		in.Source = in.Manifest.Source
	case urlGH != nil:
		in.Source = SourceGitHub
		in.DetectedBy = append(in.DetectedBy, "whereFroms:github")
	case urlListing != 0 && (c.StoreURL == "" || strings.TrimRight(c.StoreURL, "/") == urlStore):
		in.Source = SourceStore
		in.DetectedBy = append(in.DetectedBy, "whereFroms:store")
	case in.Kind == KindRARXAI:
		in.Source = SourceStore
		in.DetectedBy = append(in.DetectedBy, "extension:rarxai")
	case in.att != nil:
		in.Source = SourceStore
		in.DetectedBy = append(in.DetectedBy, "attestation")
	default:
		in.Source = SourceUnknown
	}
	if m := in.Manifest; m != nil {
		in.AppID, in.Name, in.Version, in.AgeRating, in.MinMacOS = m.AppID, m.Name, m.Version, m.AgeRating, m.MinMacOS
	}
	if in.Kind == KindApp && in.AppID == "" {
		in.AppID, in.Name, in.Version = bundleInfo(ctx, c.Engine.R, abs)
	}
	// 3. the source's own checksum
	ghSum := ""
	if in.Source == SourceGitHub {
		ref := &GitHubRef{}
		if in.Manifest != nil && in.Manifest.GitHub != nil {
			*ref = *in.Manifest.GitHub
		}
		if urlGH != nil {
			if ref.Owner == "" {
				ref.Owner, ref.Repo = urlGH.Owner, urlGH.Repo
			}
			if ref.Owner == urlGH.Owner && ref.Repo == urlGH.Repo {
				if urlGH.Tag != "" {
					ref.Tag = urlGH.Tag
				}
				if urlGH.Asset != "" {
					ref.Asset = urlGH.Asset
				}
			} else {
				in.Problems = append(in.Problems, "the file was downloaded from a different GitHub repository than its rottencore.json names")
			}
		}
		in.GitHub = ref
		ghSum = c.githubSum(ctx, in, ref, filepath.Base(abs))
	}
	if in.Source == SourceStore {
		ref := &StoreRef{URL: c.StoreURL}
		if in.Manifest != nil && in.Manifest.Store != nil {
			if in.Manifest.Store.URL != "" {
				ref.URL = in.Manifest.Store.URL
			}
			ref.ListingID = in.Manifest.Store.ListingID
		}
		if ref.ListingID == 0 && urlListing != 0 {
			ref.ListingID = urlListing
			if ref.URL == "" {
				ref.URL = urlStore
			}
		}
		in.Store = ref
		c.storeInfo(ctx, in, ref)
	}
	in.Verdict = Decide(c.Pins, sum, size, in.Manifest, in.att, ghSum)
	if in.Kind == KindApp {
		in.Verdict.Reasons = append(in.Verdict.Reasons, "a bare .app folder has no single checksum; download the .dmg, .pkg or .zip to have it checked")
	}
	if in.Listing != nil && in.AgeRating == "" {
		in.AgeRating = in.Listing.AgeRating
	}
	if in.Name == "" {
		in.Name = strings.TrimSuffix(filepath.Base(abs), filepath.Ext(abs))
	}
	if in.MinMacOS != "" {
		if have := c.macOSVersion(ctx); have != "" && CompareVersions(have, in.MinMacOS) < 0 {
			in.Problems = append(in.Problems, fmt.Sprintf("needs macOS %s or later; this Mac has %s", in.MinMacOS, have))
		}
	}
	return in, nil
}

func (c *Core) githubSum(ctx context.Context, in *Inspection, ref *GitHubRef, fileName string) string {
	if ref.Owner == "" || ref.Repo == "" {
		in.Problems = append(in.Problems, "GitHub source without a repository")
		return ""
	}
	var rel *Release
	var err error
	tags := []string{ref.Tag}
	if ref.Tag == "" && in.Version != "" {
		v := strings.TrimPrefix(in.Version, "v")
		tags = []string{"v" + v, v}
	}
	for _, t := range tags {
		if rel, err = c.Net.GitHubRelease(ctx, ref.Owner, ref.Repo, t); err == nil {
			break
		}
	}
	if err != nil {
		in.Problems = append(in.Problems, "could not read the GitHub release: "+err.Error())
		return ""
	}
	ref.Tag = rel.TagName
	in.ReleaseURL = rel.HTMLURL
	if in.Version == "" {
		in.Version = rel.ReleaseVersion()
	}
	name := ref.Asset
	if name == "" {
		name = fileName
	}
	sums, err := c.Net.Sums(ctx, rel, ref.Sums)
	if err != nil {
		in.Problems = append(in.Problems, err.Error())
		return ""
	}
	if sums == nil {
		in.Problems = append(in.Problems, "the GitHub release has no SHA256SUMS file")
		return ""
	}
	s, ok := sums[name]
	if !ok {
		in.Problems = append(in.Problems, "SHA256SUMS of "+rel.TagName+" does not list "+name)
	}
	return s
}

func (c *Core) storeInfo(ctx context.Context, in *Inspection, ref *StoreRef) {
	if ref.URL == "" {
		in.Problems = append(in.Problems, "no store URL is configured, so the store could not be asked")
		return
	}
	st := &Store{Origin: ref.URL, Net: c.Net}
	var l *Listing
	var err error
	if ref.ListingID != 0 {
		l, err = st.Get(ctx, ref.ListingID)
	} else if in.AppID != "" {
		l, err = st.Lookup(ctx, in.AppID)
	}
	if err != nil {
		in.Problems = append(in.Problems, "the store did not answer for this app: "+err.Error())
	}
	if l != nil && err == nil {
		in.Listing = l
		ref.ListingID = l.ID
		if in.AppID == "" {
			in.AppID, in.Name, in.Version = l.AppID, l.Name, l.Version
		}
	}
	if in.att == nil && ref.ListingID != 0 {
		if a, err := st.Attestation(ctx, ref.ListingID); err == nil {
			in.att = a
		} else {
			in.Problems = append(in.Problems, "the store sent no attestation: "+err.Error())
		}
	}
}

func (c *Core) macOSVersion(ctx context.Context) string {
	if runtime.GOOS != "darwin" {
		return ""
	}
	out, err := c.Engine.R.Run(ctx, "/usr/bin/sw_vers", "-productVersion")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// InstallOptions are the person's choices.
type InstallOptions struct {
	AcceptUntrusted bool   // the person accepted UntrustedWarning
	Destination     string // /Applications (default) or ~/Applications
}

// Install installs an inspected file. Checksum mismatches are refused whatever the options say.
func (c *Core) Install(ctx context.Context, in *Inspection, o InstallOptions) (*Entry, error) {
	v := in.Verdict
	if v == nil {
		return nil, errors.New("inspect the file first")
	}
	if v.Refuse {
		return nil, ErrRefused
	}
	if !v.Trusted && !o.AcceptUntrusted {
		return nil, ErrUntrusted
	}
	for _, p := range in.Problems {
		if strings.HasPrefix(p, "needs macOS") {
			return nil, errors.New(p)
		}
	}
	if in.Kind == KindRARXAI {
		return c.InstallRARXAI(ctx, in)
	}
	if o.Destination == "" && in.Manifest != nil && in.Manifest.Install != nil {
		o.Destination = in.Manifest.Install.Destination
	}
	if o.Destination != "" && !allowedDestination(o.Destination) {
		return nil, errors.New("destination must be /Applications or ~/Applications")
	}
	var spec *InstallSpec
	if in.Manifest != nil {
		spec = in.Manifest.Install
	}
	payload, kind := in.Path, in.Kind
	switch in.Kind {
	case KindZIP:
		d, err := c.Engine.Unzip(ctx, in.Path, c.TmpDir)
		if err != nil {
			return nil, err
		}
		in.cleanup = append(in.cleanup, func() { os.RemoveAll(d) })
		if payload, kind, err = FindPayload(d, spec); err != nil {
			return nil, err
		}
	case KindDMG:
		if in.mount == "" {
			return nil, errors.New("the disk image could not be opened")
		}
		var err error
		if payload, kind, err = FindPayload(in.mount, spec); err != nil {
			return nil, err
		}
	}
	e := Entry{AppID: in.AppID, Name: in.Name, Version: in.Version, Source: in.Source, Trusted: v.Trusted, TrustedBy: v.TrustedBy,
		AcceptedRisk: !v.Trusted, Kind: in.Kind, ArtifactName: filepath.Base(in.Path), SHA256: v.SHA256, Paths: []string{},
		GitHub: in.GitHub, Store: in.Store, AgeRating: in.AgeRating, InstalledAt: c.now().UTC(), UpdatedAt: c.now().UTC()}
	switch kind {
	case KindApp:
		target, cs, err := c.Engine.InstallApp(ctx, payload, o.Destination)
		if err != nil {
			return nil, err
		}
		e.Paths, e.Codesign = []string{target}, cs
		id, name, ver := bundleInfo(ctx, c.Engine.R, target)
		if in.Manifest == nil { // without a manifest the bundle's own Info.plist names the app
			e.AppID, e.Name, e.Version = firstNonEmpty(id, e.AppID), firstNonEmpty(name, e.Name), firstNonEmpty(e.Version, ver)
		}
	case KindPKG:
		var known []string
		if spec != nil {
			known = spec.PkgIDs
		}
		ids, cs, err := c.Engine.InstallPkg(ctx, payload, known)
		if err != nil {
			return nil, err
		}
		e.PkgIDs, e.Codesign = ids, cs
		if e.AppID == "" && len(ids) > 0 {
			e.AppID = ids[0]
		}
	default:
		return nil, fmt.Errorf("cannot install a %s", kind)
	}
	if e.AppID == "" {
		e.AppID = "local." + strings.ToLower(strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
				return r
			}
			return '-'
		}, e.Name))
	}
	if err := c.State.Put(e); err != nil {
		return &e, fmt.Errorf("installed, but the installed list could not be saved: %w", err)
	}
	return &e, nil
}

// Uninstall removes what RottenCore installed for an app and forgets it.
func (c *Core) Uninstall(ctx context.Context, appID string) (*Entry, error) {
	e, err := c.State.Get(appID)
	if err != nil {
		return nil, err
	}
	if e == nil {
		return nil, ErrNotInstalled
	}
	if e.Managed == "ra-launcher" {
		l, err := FindLauncher()
		if err != nil {
			return e, err
		}
		if _, err := c.Engine.R.Run(ctx, l, "uninstall", e.AppID); err != nil {
			return e, err
		}
		return e, c.State.Remove(appID)
	}
	for _, p := range e.Paths {
		if err := c.Engine.RemoveApp(ctx, p); err != nil {
			return e, err
		}
	}
	for _, id := range e.PkgIDs {
		self := c.SelfPath
		if self == "" {
			if self, err = os.Executable(); err != nil {
				return e, err
			}
		}
		if _, err := c.Engine.R.RunAdmin(ctx, self, "pkg-remove", id); err != nil {
			return e, fmt.Errorf("removing package %s: %w", id, err)
		}
	}
	return e, c.State.Remove(appID)
}

// UpdateInfo is one row of an update check.
type UpdateInfo struct {
	AppID     string `json:"appId"`
	Name      string `json:"name"`
	Source    string `json:"source"`
	Installed string `json:"installed"`
	Available string `json:"available,omitempty"`
	Newer     bool   `json:"newer"`
	Asset     string `json:"asset,omitempty"`
	Error     string `json:"error,omitempty"`
}

// CheckUpdates asks each app's source for its newest version.
func (c *Core) CheckUpdates(ctx context.Context) ([]UpdateInfo, error) {
	l, err := c.State.List()
	if err != nil {
		return nil, err
	}
	out := []UpdateInfo{}
	for _, e := range l {
		u := UpdateInfo{AppID: e.AppID, Name: e.Name, Source: e.Source, Installed: e.Version}
		switch {
		case e.Source == SourceGitHub && e.GitHub != nil:
			rel, err := c.Net.GitHubRelease(ctx, e.GitHub.Owner, e.GitHub.Repo, "")
			if err != nil {
				u.Error = err.Error()
				break
			}
			u.Available = rel.ReleaseVersion()
			u.Newer = CompareVersions(u.Available, e.Version) > 0
			if a := PickMacAsset(rel, e.GitHub.AssetPattern, e.Kind, c.Arch); a != nil {
				u.Asset = a.Name
			} else if u.Newer {
				u.Error = "the new release has no macOS installer RottenCore can pick"
			}
		case e.Source == SourceStore && e.Store != nil && e.Store.URL != "" && e.Store.ListingID != 0:
			l, err := (&Store{Origin: e.Store.URL, Net: c.Net}).Get(ctx, e.Store.ListingID)
			if err != nil {
				u.Error = err.Error()
				break
			}
			u.Available = l.Version
			u.Newer = CompareVersions(l.Version, e.Version) > 0
		default:
			u.Error = "no update source is known for this app"
		}
		out = append(out, u)
	}
	return out, nil
}

// FetchGitHub downloads the macOS installer of a release (latest when tag is "") and inspects it. The
// caller Installs and Closes. pattern/preferKind pick the asset (PickMacAsset).
func (c *Core) FetchGitHub(ctx context.Context, owner, repo, tag, pattern, preferKind string, progress func(int64, int64)) (*Inspection, error) {
	rel, err := c.Net.GitHubRelease(ctx, owner, repo, tag)
	if err != nil {
		return nil, err
	}
	a := PickMacAsset(rel, pattern, preferKind, c.Arch)
	if a == nil {
		return nil, fmt.Errorf("%s/%s %s has no macOS installer (.dmg, .pkg or .zip) RottenCore can pick", owner, repo, rel.TagName)
	}
	if err := os.MkdirAll(c.TmpDir, 0o700); err != nil {
		return nil, err
	}
	d, err := os.MkdirTemp(c.TmpDir, "dl-")
	if err != nil {
		return nil, err
	}
	dst := filepath.Join(d, a.Name)
	if _, _, err := c.Net.Download(ctx, a.URL, dst, progress); err != nil {
		os.RemoveAll(d)
		return nil, err
	}
	in, err := c.Inspect(ctx, dst, &Hint{GitHub: &GitHubRef{Owner: owner, Repo: repo, Tag: rel.TagName, Asset: a.Name, AssetPattern: pattern}})
	if err != nil {
		os.RemoveAll(d)
		return nil, err
	}
	in.DownloadURL = a.URL
	in.cleanup = append([]func(){func() { os.RemoveAll(d) }}, in.cleanup...)
	if in.GitHub != nil && in.GitHub.AssetPattern == "" {
		in.GitHub.AssetPattern = pattern
	}
	return in, nil
}

// PrepareUpdate downloads and inspects the newest build of an installed app. GitHub apps only: store
// apps are updated by the Rotten Apple launcher (the store download needs a signed-in account).
func (c *Core) PrepareUpdate(ctx context.Context, appID string, progress func(int64, int64)) (*Inspection, error) {
	e, err := c.State.Get(appID)
	if err != nil {
		return nil, err
	}
	if e == nil {
		return nil, ErrNotInstalled
	}
	if e.Source != SourceGitHub || e.GitHub == nil {
		return nil, errors.New("only GitHub apps update through RottenCore yet; store apps update in the Rotten Apple launcher")
	}
	in, err := c.FetchGitHub(ctx, e.GitHub.Owner, e.GitHub.Repo, "", e.GitHub.AssetPattern, e.Kind, progress)
	if err != nil {
		return nil, err
	}
	if in.AppID != "" && in.AppID != e.AppID && in.Manifest != nil {
		in.Close()
		return nil, fmt.Errorf("the new release says it is %s, not %s; not installed", in.AppID, e.AppID)
	}
	if in.AppID == "" {
		in.AppID = e.AppID
	}
	return in, nil
}
