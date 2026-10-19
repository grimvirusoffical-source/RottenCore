package core

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Listing is the part of a Rotten Apple store listing RottenCore shows and uses
// (GET /v1/catalog/apps/{id}, /v1/catalog/lookup?appId=, GET /v1/catalog/apps?q=).
type Listing struct {
	ID            int64    `json:"id"`
	AppID         string   `json:"appId"`
	Name          string   `json:"name"`
	Tagline       string   `json:"tagline"`
	Description   string   `json:"description,omitempty"`
	Genres        []string `json:"genres,omitempty"`
	AgeRating     string   `json:"ageRating"`
	ContentFlags  []string `json:"contentFlags,omitempty"`
	MinOS         string   `json:"minOS,omitempty"`
	Archs         []string `json:"archs,omitempty"`
	Platforms     []string `json:"platforms,omitempty"`
	PriceCents    int64    `json:"priceCents"`
	Version       string   `json:"version"`
	Build         int      `json:"build,omitempty"`
	PackageSHA256 string   `json:"packageSha256,omitempty"`
	PackageBytes  int64    `json:"packageBytes,omitempty"`
}

// Store talks to one Rotten Apple store origin. Reads are anonymous (all-ages apps only, as the store
// rules); a session token, once Red-XAI Accounts exists, comes through the Accounts interface.
type Store struct {
	Origin string
	Net    *Net
}

func (s *Store) url(p string) (string, error) {
	if !ValidOrigin(s.Origin, s.Net.AllowLoopbackHTTP) {
		return "", fmt.Errorf("the store URL %q is not an https origin (set storeURL in the RottenCore config)", s.Origin)
	}
	return strings.TrimRight(s.Origin, "/") + p, nil
}

// Search lists macOS apps matching q.
func (s *Store) Search(ctx context.Context, q string, limit int) ([]Listing, error) {
	u, err := s.url("/v1/catalog/apps?platform=macos&q=" + url.QueryEscape(q) + "&limit=" + strconv.Itoa(limit))
	if err != nil {
		return nil, err
	}
	out := []Listing{}
	return out, s.Net.GetJSON(ctx, u, &out)
}

// Get fetches one listing by id.
func (s *Store) Get(ctx context.Context, id int64) (*Listing, error) {
	u, err := s.url("/v1/catalog/apps/" + strconv.FormatInt(id, 10))
	if err != nil {
		return nil, err
	}
	var l Listing
	return &l, s.Net.GetJSON(ctx, u, &l)
}

// Lookup fetches a listing by bundle id.
func (s *Store) Lookup(ctx context.Context, appID string) (*Listing, error) {
	u, err := s.url("/v1/catalog/lookup?appId=" + url.QueryEscape(appID))
	if err != nil {
		return nil, err
	}
	var l Listing
	if err := s.Net.GetJSON(ctx, u, &l); err != nil {
		return nil, err
	}
	if l.AppID != appID {
		return nil, fmt.Errorf("the store returned %q for %q", l.AppID, appID)
	}
	return &l, nil
}

// Attestation fetches the store's signed attestation for a listing's live package.
func (s *Store) Attestation(ctx context.Context, id int64) (*Signed, error) {
	u, err := s.url("/v1/catalog/apps/" + strconv.FormatInt(id, 10) + "/attestation")
	if err != nil {
		return nil, err
	}
	var sg Signed
	return &sg, s.Net.GetJSON(ctx, u, &sg)
}

// listingFromURL reads a listing id from a store download URL (…/v1/catalog/apps/{id}/download).
func listingFromURL(raw string) (origin string, id int64, ok bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", 0, false
	}
	p := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(p) == 5 && p[0] == "v1" && p[1] == "catalog" && p[2] == "apps" && p[4] == "download" {
		if n, err := strconv.ParseInt(p[3], 10, 64); err == nil && n > 0 {
			return u.Scheme + "://" + u.Host, n, true
		}
	}
	return "", 0, false
}

// githubFromURL reads owner, repo, tag and asset from a release download URL
// (https://github.com/<owner>/<repo>/releases/download/<tag>/<asset>).
func githubFromURL(raw string) (*GitHubRef, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || (u.Host != "github.com" && u.Host != "www.github.com") {
		return nil, false
	}
	p := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(p) == 6 && p[2] == "releases" && p[3] == "download" {
		g := &GitHubRef{Owner: p[0], Repo: p[1], Tag: p[4], Asset: p[5]}
		if ghNameRe.MatchString(g.Owner) && ghNameRe.MatchString(g.Repo) && ghNameRe.MatchString(g.Tag) && fileRe.MatchString(g.Asset) {
			return g, true
		}
	}
	return nil, false
}
