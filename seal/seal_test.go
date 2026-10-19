package seal

import (
	"bytes"
	"testing"
)

type rev struct{}

func (rev) ID() string { return "test-reverse" }
func (rev) Seal(_ Purpose, b, _ []byte) ([]byte, error) {
	o := append([]byte{}, b...)
	for i, j := 0, len(o)-1; i < j; i, j = i+1, j-1 {
		o[i], o[j] = o[j], o[i]
	}
	return o, nil
}
func (r rev) Open(p Purpose, b, a []byte) ([]byte, error) { return r.Seal(p, b, a) }

func TestNoopByDefaultAndPluggable(t *testing.T) {
	if Active() || Current().ID() != NoopID {
		t.Fatal("encryption must be off by default")
	}
	in := []byte("plain")
	out, _ := Current().Seal(PrivateKey, in, nil)
	if !bytes.Equal(in, out) {
		t.Fatal("noop changed bytes")
	}
	Register(rev{})
	defer Register(nil)
	out, _ = Current().Seal(Upload, in, nil)
	back, _ := Current().Open(Upload, out, nil)
	if !Active() || bytes.Equal(out, in) || !bytes.Equal(back, in) {
		t.Fatal("registered sealer not used")
	}
}
