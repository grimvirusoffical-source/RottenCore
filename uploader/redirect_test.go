package uploader

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/grimvirusoffical-source/RottenCore/core"
	"github.com/grimvirusoffical-source/RottenCore/devhub"
)

// QA D3: uploads carry the build key (and X-Chunk-* headers); the store client never follows a redirect.
func TestStoreNeverFollowsRedirects(t *testing.T) {
	var otherHits int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&otherHits, 1) }))
	defer other.Close()
	otherURL := strings.Replace(other.URL, "127.0.0.1", "localhost", 1)
	for _, status := range []int{307, 302} {
		for _, same := range []bool{false, true} {
			var sameHits int32
			hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/moved") {
					atomic.AddInt32(&sameHits, 1)
					return
				}
				to := otherURL + "/moved"
				if same {
					to = "/moved"
				}
				http.Redirect(w, r, to, status)
			}))
			s := &RACoreStore{Base: hub.URL, AllowLoopbackHTTP: true, Ctx: &devhub.BuildContext{BuildKey: "ra_sk_live_build"}}
			err := s.do(context.Background(), "POST", "/v1/devhub/uploads", map[string]string{"X-Chunk-SHA256": "x"}, strings.NewReader("{}"), nil)
			var re *core.RedirectError
			if !errors.As(err, &re) || re.Status != status {
				t.Errorf("%d same=%v: want RedirectError, got %v", status, same, err)
			}
			if atomic.LoadInt32(&otherHits) != 0 || atomic.LoadInt32(&sameHits) != 0 {
				t.Fatalf("%d same=%v: redirect followed", status, same)
			}
			hub.Close()
		}
	}
}
