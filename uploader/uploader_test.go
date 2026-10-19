package uploader

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/grimvirusoffical-source/RottenCore/core"
	"github.com/grimvirusoffical-source/RottenCore/devhub"
)

// fakeRACore is a minimal chunked upload API: POST /v1/uploads, PUT chunks (checks X-Chunk-SHA256),
// POST commit.
func fakeRACore(t *testing.T, chunkSize int64) (*httptest.Server, func() []byte, func() string) {
	var mu sync.Mutex
	chunks := map[int64][]byte{}
	var auth string
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/uploads", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auth = r.Header.Get("Authorization")
		mu.Unlock()
		var req struct {
			Size   int64  `json:"size"`
			SHA256 string `json:"sha256"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		n := (req.Size + chunkSize - 1) / chunkSize
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(UploadInfo{ID: "up_1", Size: req.Size, ChunkSize: chunkSize, Chunks: n, State: "open"})
	})
	mux.HandleFunc("PUT /v1/uploads/{id}/chunks/{n}", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		cs := sha256.Sum256(body)
		if r.Header.Get("X-Chunk-SHA256") != hex.EncodeToString(cs[:]) {
			w.WriteHeader(400)
			w.Write([]byte(`{"error":"bad chunk hash"}`))
			return
		}
		var n int64
		fmt.Sscan(r.PathValue("n"), &n)
		mu.Lock()
		chunks[n] = body
		mu.Unlock()
		w.WriteHeader(204)
	})
	mux.HandleFunc("POST /v1/uploads/{id}/commit", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Build{ID: 7, App: "com.redx.quicklaunch", Version: "1.0.0", State: "uploaded"})
	})
	assembled := func() []byte {
		mu.Lock()
		defer mu.Unlock()
		var out []byte
		for i := int64(0); i < int64(len(chunks)); i++ {
			out = append(out, chunks[i]...)
		}
		return out
	}
	return httptest.NewServer(mux), assembled, func() string { return auth }
}

func TestChunkedUploadRealProgressAndBuildKey(t *testing.T) {
	srv, assembled, authOf := fakeRACore(t, 8)
	defer srv.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "quicklaunch-1.0.0-macos-arm64.dmg")
	content := []byte("this is a fake dmg of twenty-nine!!") // 35 bytes -> 5 chunks of 8
	os.WriteFile(path, content, 0o644)

	// no build key -> the exact ErrNoBuildKey
	noKey := &RACoreStore{Base: srv.URL, AllowLoopbackHTTP: true, Ctx: &devhub.BuildContext{Role: "developer"}}
	if _, err := noKey.Upload(context.Background(), path, nil); err != devhub.ErrNoBuildKey {
		t.Fatalf("missing build key: %v", err)
	}

	var seen []int64
	s := &RACoreStore{Base: srv.URL, AllowLoopbackHTTP: true, Ctx: &devhub.BuildContext{Role: "developer", BuildKey: "ra_sk_test"}}
	b, err := s.Upload(context.Background(), path, func(done, total int64) { seen = append(seen, done) })
	if err != nil {
		t.Fatal(err)
	}
	if b.ID != 7 || authOf() != "Bearer ra_sk_test" {
		t.Fatalf("build %+v auth %q", b, authOf())
	}
	// the store reassembled exactly the file bytes (no encryption changed them)
	if string(assembled()) != string(content) {
		t.Fatalf("assembled %q", assembled())
	}
	// progress is real and monotonic, ending at the full size
	if len(seen) == 0 || seen[len(seen)-1] != int64(len(content)) {
		t.Fatalf("progress %v", seen)
	}
	for i := 1; i < len(seen); i++ {
		if seen[i] < seen[i-1] {
			t.Fatal("progress went backwards")
		}
	}
}

func TestFreeUnlimitedShownForOwnersAndAdmins(t *testing.T) {
	for _, role := range []string{"owner", "admin"} {
		s := &RACoreStore{Ctx: &devhub.BuildContext{Role: role, BuildKey: "k"}}
		if !s.FreeUnlimited() {
			t.Fatalf("%s should show unlimited free uploads", role)
		}
	}
	s := &RACoreStore{Ctx: &devhub.BuildContext{Role: "developer", BuildKey: "k"}}
	if s.FreeUnlimited() {
		t.Fatal("developer is not unlimited free")
	}
}

type fakeQA struct{ ok bool }

func (q fakeQA) SignedOff(ctx context.Context, app, version string) (QAStatus, error) {
	return QAStatus{App: app, Version: version, SignedOff: q.ok}, nil
}

type recordTarget struct{ published bool }

func (r *recordTarget) Name() string { return "test" }
func (r *recordTarget) PublishRelease(ctx context.Context, app string, req core.PublishRequest) error {
	r.published = true
	return nil
}

func TestPublishBlockedUntilQASignsOff(t *testing.T) {
	ctx := context.Background()
	key := &devhub.BuildContext{Role: "developer", BuildKey: "ra_sk"}
	req := core.PublishRequest{Version: "1.0.0", Tag: "v1.0.0", Assets: []core.ReleaseAsset{{URL: "https://github.com/grimvirusoffical-source/quick-launch/releases/download/v1.0.0/a.dmg"}}}

	// not signed off -> blocked, target never called
	tgt := &recordTarget{}
	p := &Publisher{QA: fakeQA{ok: false}, Ctx: key}
	if err := p.Publish(ctx, tgt, "com.redx.quicklaunch", "1.0.0", req); err == nil || tgt.published {
		t.Fatalf("published without QA sign-off: %v published=%v", err, tgt.published)
	}
	// no QA gate at all -> blocked
	if err := (&Publisher{Ctx: key}).Publish(ctx, tgt, "a", "1", req); err != ErrQANotSignedOff {
		t.Fatalf("nil gate: %v", err)
	}
	// missing build key -> ErrNoBuildKey
	if err := (&Publisher{QA: fakeQA{ok: true}, Ctx: &devhub.BuildContext{Role: "developer"}}).Publish(ctx, tgt, "a", "1", req); err != devhub.ErrNoBuildKey {
		t.Fatalf("missing key: %v", err)
	}
	// signed off -> publishes
	p = &Publisher{QA: fakeQA{ok: true}, Ctx: key}
	if err := p.Publish(ctx, tgt, "com.redx.quicklaunch", "1.0.0", req); err != nil || !tgt.published {
		t.Fatalf("signed-off publish: %v", err)
	}
}
