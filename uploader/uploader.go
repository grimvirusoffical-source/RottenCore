// Package uploader uploads a developer's built, signed artifacts to the Rotten Apple store (ra-core) or,
// through adapters, to other stores (a Red-XAI Host / GitHub release via core.HostClient.Publish).
//
// It needs a build API key (devhub.BuildContext); without one it returns devhub.ErrNoBuildKey. Owners and
// admins upload unlimited and free — the server enforces that; the client only shows it (FreeUnlimited).
// Publishing a public release is blocked until QA signs off (QAGate). Nothing is encrypted: the request body
// passes through the seal hook (ENCRYPTION-HOOK uploader.body), a no-op by default.
package uploader

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/grimvirusoffical-source/RottenCore/core"
	"github.com/grimvirusoffical-source/RottenCore/devhub"
	"github.com/grimvirusoffical-source/RottenCore/seal"
)

// UploadInfo mirrors ra-core POST /v1/uploads (and GET /v1/uploads/{id}).
type UploadInfo struct {
	ID        string  `json:"id"`
	Size      int64   `json:"size"`
	ChunkSize int64   `json:"chunkSize"`
	Chunks    int64   `json:"chunks"`
	Received  []int64 `json:"received"`
	State     string  `json:"state"`
	BuildID   int64   `json:"buildId,omitempty"`
}

// Build is ra-core's commit response (a created build).
type Build struct {
	ID      int64  `json:"id"`
	App     string `json:"app"`
	Version string `json:"version"`
	State   string `json:"state"`
}

// Store is where artifacts land.
type Store interface {
	// Upload sends one file with real byte progress and returns the created build.
	Upload(ctx context.Context, path string, progress func(done, total int64)) (*Build, error)
	// Name is a short label for the UI.
	Name() string
}

// RACoreStore is the Rotten Apple store (ra-core) chunked, resumable upload API.
type RACoreStore struct {
	Base string // https origin, e.g. https://api.rottenapplestore.org
	Ctx  *devhub.BuildContext
	Net  *core.Net
	// AllowLoopbackHTTP is for tests.
	AllowLoopbackHTTP bool
	// Resume is an existing upload id to continue (optional).
	Resume string
}

func (s *RACoreStore) Name() string { return "Rotten Apple store" }

// FreeUnlimited reports whether this account uploads unlimited and free (owners and admins). Display only;
// ra-core enforces the quota and fee server-side.
func (s *RACoreStore) FreeUnlimited() bool {
	return s.Ctx != nil && s.Ctx.Exempt()
}

func (s *RACoreStore) http() *http.Client {
	n := s.Net
	if n == nil {
		n = &core.Net{AllowLoopbackHTTP: s.AllowLoopbackHTTP}
	}
	c := *core.NoRedirects(n.ClientForUploads()) // build key never follows a redirect (QA D3)
	return &c
}

func (s *RACoreStore) do(ctx context.Context, method, path string, hdr map[string]string, body io.Reader, out interface{}) error {
	if !core.ValidOrigin(s.Base, s.AllowLoopbackHTTP) {
		return fmt.Errorf("store %q is not an https origin", s.Base)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.Base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "RottenCore/"+core.Version)
	if s.Ctx != nil && s.Ctx.BuildKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.Ctx.BuildKey)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := s.http().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := core.RefuseRedirect(resp); err != nil {
		return err
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &StoreError{Status: resp.StatusCode, Body: string(bytes.TrimSpace(b))}
	}
	if out != nil && len(bytes.TrimSpace(b)) > 0 {
		return json.Unmarshal(b, out)
	}
	return nil
}

// StoreError is a non-2xx answer from ra-core.
type StoreError struct {
	Status int
	Body   string
}

func (e *StoreError) Error() string { return fmt.Sprintf("store answered %d: %s", e.Status, e.Body) }

// Upload runs the chunked, resumable upload with real byte progress and per-chunk X-Chunk-SHA256.
func (s *RACoreStore) Upload(ctx context.Context, path string, progress func(done, total int64)) (*Build, error) {
	if err := s.Ctx.RequireBuildKey(); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	sum, err := fileSHA256(f)
	if err != nil {
		return nil, err
	}

	var info UploadInfo
	if s.Resume != "" {
		if err := s.do(ctx, "GET", "/v1/uploads/"+url.PathEscape(s.Resume), nil, nil, &info); err != nil {
			return nil, err
		}
		if info.Size != st.Size() {
			return nil, errors.New("the file size differs from the upload being resumed")
		}
	} else {
		reqBody := map[string]interface{}{"size": st.Size(), "sha256": sum}
		b, _ := json.Marshal(reqBody)
		if err := s.do(ctx, "POST", "/v1/uploads", map[string]string{"Content-Type": "application/json"}, bytes.NewReader(b), &info); err != nil {
			return nil, err
		}
	}

	have := map[int64]bool{}
	var sent int64
	for _, n := range info.Received {
		have[n] = true
		sent += chunkLen(&info, n)
	}
	if progress != nil {
		progress(sent, info.Size)
	}
	buf := make([]byte, info.ChunkSize)
	for n := int64(0); n < info.Chunks; n++ {
		if have[n] {
			continue
		}
		want := chunkLen(&info, n)
		if _, err := f.ReadAt(buf[:want], n*info.ChunkSize); err != nil && err != io.EOF {
			return nil, err
		}
		// ENCRYPTION-HOOK: uploader.body -- each chunk's bytes before they are hashed and sent. The default
		// Sealer is a no-op, so the chunk is uploaded verbatim and X-Chunk-SHA256 covers exactly what the
		// store stores. DON'T ENCRYPT ANYTHING by default.
		sealed, err := seal.Current().Seal(seal.Upload, buf[:want], []byte(fmt.Sprintf("upload:%s:%d", info.ID, n)))
		if err != nil {
			return nil, err
		}
		cs := sha256.Sum256(sealed)
		hdr := map[string]string{"X-Chunk-SHA256": hex.EncodeToString(cs[:]), "Content-Type": "application/octet-stream"}
		if err := s.do(ctx, "PUT", fmt.Sprintf("/v1/uploads/%s/chunks/%d", url.PathEscape(info.ID), n), hdr, bytes.NewReader(sealed), nil); err != nil {
			return nil, fmt.Errorf("chunk %d: %w (resume with the upload id %s)", n, err, info.ID)
		}
		sent += want
		if progress != nil {
			progress(sent, info.Size)
		}
	}
	var build Build
	if err := s.do(ctx, "POST", "/v1/uploads/"+url.PathEscape(info.ID)+"/commit", nil, nil, &build); err != nil {
		return nil, err
	}
	return &build, nil
}

func chunkLen(i *UploadInfo, n int64) int64 {
	if i.ChunkSize == 0 {
		return 0
	}
	if n == i.Chunks-1 {
		return i.Size - n*i.ChunkSize
	}
	return i.ChunkSize
}

func fileSHA256(f *os.File) (string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

var _ = time.Now
