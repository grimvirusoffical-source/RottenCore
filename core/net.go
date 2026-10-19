package core

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// MaxDownload caps one download (4 GiB).
const MaxDownload int64 = 4 << 30

// ValidOrigin accepts https URLs, and http only for loopback hosts when allowLoopbackHTTP is set (tests
// and a developer's local store).
func ValidOrigin(raw string, allowLoopbackHTTP bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme == "http" && allowLoopbackHTTP {
		h := u.Hostname()
		if h == "localhost" {
			return true
		}
		ip := net.ParseIP(h)
		return ip != nil && ip.IsLoopback()
	}
	return false
}

// Net is the HTTP side. Every URL it fetches must pass ValidOrigin, redirects included.
type Net struct {
	HTTP              *http.Client
	AllowLoopbackHTTP bool
	UserAgent         string
	GitHubAPI         string // default https://api.github.com
	// GitHubToken (env ROTTENCORE_GITHUB_TOKEN, optional) is sent only to the GitHub API host, only to lift
	// the anonymous rate limit. RottenCore needs no token: it reads public releases.
	GitHubToken string
}

func (n *Net) client() *http.Client {
	base := n.HTTP
	if base == nil {
		base = &http.Client{Timeout: 30 * time.Minute}
	}
	c := *base
	c.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if len(via) > 5 {
			return errors.New("too many redirects")
		}
		if !ValidOrigin(r.URL.Scheme+"://"+r.URL.Host, n.AllowLoopbackHTTP) {
			return fmt.Errorf("refusing a redirect to %s (not https)", r.URL.Host)
		}
		return nil
	}
	return &c
}

func (n *Net) get(ctx context.Context, raw string, accept string) (*http.Response, error) {
	u, err := url.Parse(raw)
	if err != nil || !ValidOrigin(u.Scheme+"://"+u.Host, n.AllowLoopbackHTTP) {
		return nil, fmt.Errorf("refusing to fetch %q: only https is allowed", raw)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", raw, nil)
	if err != nil {
		return nil, err
	}
	ua := n.UserAgent
	if ua == "" {
		ua = "RottenCore/" + Version
	}
	req.Header.Set("User-Agent", ua)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if n.GitHubToken != "" {
		if api, err := url.Parse(n.ghAPI()); err == nil && api.Host == u.Host && u.Scheme == "https" {
			req.Header.Set("Authorization", "Bearer "+n.GitHubToken)
		}
	}
	resp, err := n.client().Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()
		return nil, &HTTPError{Status: resp.StatusCode, URL: raw, Body: strings.TrimSpace(string(b))}
	}
	return resp, nil
}

// HTTPError is a non-200 answer.
type HTTPError struct {
	Status int
	URL    string
	Body   string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("%s answered %d", e.URL, e.Status) }

// GetJSON fetches and decodes JSON (at most 8 MB).
func (n *Net) GetJSON(ctx context.Context, raw string, out interface{}) error {
	resp, err := n.get(ctx, raw, "application/json")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
}

// GetSmall fetches a small text file (at most 1 MB).
func (n *Net) GetSmall(ctx context.Context, raw string) ([]byte, error) {
	resp, err := n.get(ctx, raw, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err == nil && len(b) > 1<<20 {
		err = errors.New("file larger than 1 MB")
	}
	return b, err
}

// Download writes raw to dst (via dst.part) and returns its sha256 and size.
func (n *Net) Download(ctx context.Context, raw, dst string, progress func(done, total int64)) (string, int64, error) {
	resp, err := n.get(ctx, raw, "application/octet-stream")
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.ContentLength > MaxDownload {
		return "", 0, errors.New("download is larger than 4 GiB")
	}
	tmp := dst + ".part"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", 0, err
	}
	h := sha256.New()
	var w io.Writer = io.MultiWriter(f, h)
	if progress != nil {
		w = &progressWriter{w: w, total: resp.ContentLength, fn: progress}
	}
	sz, err := io.Copy(w, io.LimitReader(resp.Body, MaxDownload+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && sz > MaxDownload {
		err = errors.New("download is larger than 4 GiB")
	}
	if err == nil && resp.ContentLength >= 0 && sz != resp.ContentLength {
		err = io.ErrUnexpectedEOF
	}
	if err == nil {
		err = os.Rename(tmp, dst)
	}
	if err != nil {
		os.Remove(tmp)
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), sz, nil
}

type progressWriter struct {
	w     io.Writer
	done  int64
	total int64
	fn    func(int64, int64)
}

func (p *progressWriter) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	p.done += int64(n)
	p.fn(p.done, p.total)
	return n, err
}

// FileSHA256 hashes a file.
func FileSHA256(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// ParseSHA256SUMS reads `sha256sum` output ("<hex>  <name>" or "<hex> *<name>") into name -> hex.
func ParseSHA256SUMS(b []byte) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	line := 0
	for sc.Scan() {
		line++
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		f := strings.Fields(t)
		if len(f) != 2 {
			return nil, fmt.Errorf("SHA256SUMS line %d is not \"<sha256>  <file>\"", line)
		}
		sum, name := strings.ToLower(f[0]), strings.TrimPrefix(f[1], "*")
		name = strings.TrimPrefix(name, "./")
		if !sha256Re.MatchString(sum) || !fileRe.MatchString(name) {
			return nil, fmt.Errorf("SHA256SUMS line %d is malformed", line)
		}
		if old, dup := out[name]; dup && old != sum {
			return nil, fmt.Errorf("SHA256SUMS lists %s twice with different sums", name)
		}
		out[name] = sum
	}
	return out, sc.Err()
}
