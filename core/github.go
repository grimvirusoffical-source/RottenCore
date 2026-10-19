package core

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// Release is the part of a GitHub release RottenCore uses.
type Release struct {
	TagName    string  `json:"tag_name"`
	Name       string  `json:"name"`
	Draft      bool    `json:"draft"`
	Prerelease bool    `json:"prerelease"`
	HTMLURL    string  `json:"html_url"`
	Assets     []Asset `json:"assets"`
}

// Asset is one release file.
type Asset struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	URL  string `json:"browser_download_url"`
}

func (n *Net) ghAPI() string {
	if n.GitHubAPI != "" {
		return strings.TrimRight(n.GitHubAPI, "/")
	}
	return "https://api.github.com"
}

// GitHubRelease fetches a release by tag, or the latest when tag is "". Public repositories only: no
// token is ever sent.
func (n *Net) GitHubRelease(ctx context.Context, owner, repo, tag string) (*Release, error) {
	if !ghNameRe.MatchString(owner) || !ghNameRe.MatchString(repo) || (tag != "" && !ghNameRe.MatchString(tag)) {
		return nil, fmt.Errorf("invalid GitHub repository %q/%q", owner, repo)
	}
	u := n.ghAPI() + "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/releases/"
	if tag == "" {
		u += "latest"
	} else {
		u += "tags/" + url.PathEscape(tag)
	}
	var r Release
	if err := n.GetJSON(ctx, u, &r); err != nil {
		return nil, err
	}
	if r.TagName == "" {
		return nil, fmt.Errorf("GitHub returned a release without a tag for %s/%s", owner, repo)
	}
	return &r, nil
}

// Asset finds an asset by exact name.
func (r *Release) Asset(name string) *Asset {
	for i := range r.Assets {
		if r.Assets[i].Name == name {
			return &r.Assets[i]
		}
	}
	return nil
}

// ReleaseVersion is the tag without a leading "v".
func (r *Release) ReleaseVersion() string { return strings.TrimPrefix(r.TagName, "v") }

// Sums downloads and parses the release's checksum file (default SHA256SUMS). nil, nil when there is none.
func (n *Net) Sums(ctx context.Context, r *Release, name string) (map[string]string, error) {
	if name == "" {
		name = "SHA256SUMS"
	}
	a := r.Asset(name)
	if a == nil {
		return nil, nil
	}
	b, err := n.GetSmall(ctx, a.URL)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", name, err)
	}
	return ParseSHA256SUMS(b)
}

// PickMacAsset chooses the asset of a release to install: AssetPattern when given, otherwise the best
// macOS installer (universal before this machine's chip, the same kind as before when possible).
func PickMacAsset(r *Release, pattern, preferKind, arch string) *Asset {
	if pattern != "" {
		return r.Asset(strings.ReplaceAll(pattern, "{version}", r.ReleaseVersion()))
	}
	best, bestScore := (*Asset)(nil), 0
	for i := range r.Assets {
		a := &r.Assets[i]
		l := strings.ToLower(a.Name)
		k := KindOf(l)
		if k != KindDMG && k != KindPKG && k != KindZIP {
			continue
		}
		if !strings.Contains(l, "mac") && !strings.Contains(l, "darwin") && !strings.Contains(l, "osx") {
			continue
		}
		s := 1
		switch {
		case strings.Contains(l, "universal"):
			s += 4
		case arch == "arm64" && (strings.Contains(l, "arm64") || strings.Contains(l, "aarch64")):
			s += 3
		case arch == "x86_64" && (strings.Contains(l, "amd64") || strings.Contains(l, "x86_64") || strings.Contains(l, "x64")):
			s += 3
		case strings.Contains(l, "arm64") || strings.Contains(l, "amd64") || strings.Contains(l, "x86_64"):
			continue // the other chip
		}
		if k == preferKind {
			s += 2
		} else if k == KindDMG {
			s++
		}
		if s > bestScore {
			best, bestScore = a, s
		}
	}
	return best
}
