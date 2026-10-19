package builder

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
)

// BuildIDRe is the strict build-id format shared by the Go inbox and the Swift URL handler (QA v2 N3).
// Same shape QuickLaunch writes; anything with path separators or dots is refused before it touches the disk.
var BuildIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

// ErrBadBuildID is returned when the id is not BuildIDRe (traversal attempts land here).
var ErrBadBuildID = errors.New("build id must be 8-64 characters of [A-Za-z0-9_-]")

// ErrInboxEscape is returned when the resolved request path is outside the inbox directory.
var ErrInboxEscape = errors.New("build request path escapes the inbox")

// ErrInboxPerms is returned when the request file is not a regular file owned by this user with mode 0600.
var ErrInboxPerms = errors.New("build request must be a regular file owned by you with mode 0600")

// ErrIDMismatch is returned when the JSON id field does not equal the inbox file name (without .json).
var ErrIDMismatch = errors.New("build request id does not match the inbox file name")

// ErrConfirmRequired is returned by build-inbox when --yes was not passed (the app must show a confirm sheet).
var ErrConfirmRequired = errors.New("confirm the build before it runs (pass --yes after the user confirms)")

// InboxDir is <supportDir>/build-requests.
func InboxDir(supportDir string) string {
	return filepath.Join(supportDir, "build-requests")
}

// ValidateBuildID enforces BuildIDRe.
func ValidateBuildID(id string) error {
	if !BuildIDRe.MatchString(id) {
		return ErrBadBuildID
	}
	return nil
}

// InboxPath is where QuickLaunch drops a request. It validates the id first so a traversal like
// ../../../../../evil/evil never becomes a path.
func InboxPath(supportDir, id string) (string, error) {
	if err := ValidateBuildID(id); err != nil {
		return "", err
	}
	return filepath.Join(InboxDir(supportDir), id+".json"), nil
}

// OpenInboxRequest loads a request by id with every N3 check: strict id, resolved path inside the inbox
// (no symlink escape), owner-only mode 0600, and JSON id == file id. It does not delete the file.
func OpenInboxRequest(supportDir, id string) (req *Request, targets []Target, path string, err error) {
	path, err = InboxPath(supportDir, id)
	if err != nil {
		return nil, nil, "", err
	}
	if err := assertInboxDir(supportDir); err != nil {
		return nil, nil, "", err
	}
	if err := assertInsideInbox(supportDir, path); err != nil {
		return nil, nil, "", err
	}
	if err := assertInboxPerms(path); err != nil {
		return nil, nil, "", err
	}
	req, targets, err = ReadRequest(path)
	if err != nil {
		return nil, nil, "", err
	}
	if req.ID != id {
		return nil, nil, "", fmt.Errorf("%w: file %q claims id %q", ErrIDMismatch, id, req.ID)
	}
	return req, targets, path, nil
}

// ConsumeRequest deletes a request file after a successful (or abandoned) build so it cannot be replayed.
func ConsumeRequest(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Preview is the confirmation payload the app (and `build-inbox` without --yes) shows before any build runs.
type Preview struct {
	ID      string          `json:"id"`
	App     string          `json:"app"`
	AppID   string          `json:"appId"`
	Version string          `json:"version"`
	Channel string          `json:"channel,omitempty"`
	Dir     string          `json:"dir"`
	Targets []PreviewTarget `json:"targets"`
	SDKs    []string        `json:"sdks,omitempty"`
	Path    string          `json:"path"`
	Message string          `json:"message"`
}

// PreviewTarget is one row of the confirmation sheet.
type PreviewTarget struct {
	Platform string   `json:"platform"`
	Command  []string `json:"command,omitempty"`
	Env      []string `json:"env,omitempty"`
	Prebuilt string   `json:"prebuilt,omitempty"`
	Artifact string   `json:"artifact,omitempty"`
}

// MakePreview builds the confirmation sheet payload from an opened request.
func MakePreview(req *Request, targets []Target, path string) Preview {
	pt := make([]PreviewTarget, 0, len(targets))
	for _, t := range targets {
		pt = append(pt, PreviewTarget{Platform: t.Platform, Command: t.Command, Env: t.Env, Prebuilt: t.Prebuilt, Artifact: t.Artifact})
	}
	return Preview{
		ID: req.ID, App: req.Project.Name, AppID: req.Project.ID, Version: req.Project.Version,
		Channel: req.Project.Channel, Dir: req.Project.Dir, Targets: pt, SDKs: req.SDKs, Path: path,
		Message: ErrConfirmRequired.Error(),
	}
}

func assertInsideInbox(supportDir, path string) error {
	inbox, err := filepath.Abs(InboxDir(supportDir))
	if err != nil {
		return err
	}
	// Resolve symlinks on the directory chain and on the file itself so a symlink under the inbox
	// that points outside is still caught.
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		// File may not exist yet for EvalSymlinks on the leaf; resolve the parent and rejoin the base.
		parent, base := filepath.Dir(path), filepath.Base(path)
		rp, perr := filepath.EvalSymlinks(parent)
		if perr != nil {
			// Parent may also be missing (empty inbox); fall back to Abs of the joined path.
			abs, aerr := filepath.Abs(path)
			if aerr != nil {
				return err
			}
			resolved = abs
		} else {
			resolved = filepath.Join(rp, base)
		}
	}
	inboxResolved, err := filepath.EvalSymlinks(inbox)
	if err != nil {
		inboxResolved = inbox
	}
	rel, err := filepath.Rel(inboxResolved, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("%w: %s", ErrInboxEscape, path)
	}
	return nil
}

func assertInboxPerms(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: request file must not be a symlink", ErrInboxEscape)
	}
	if !fi.Mode().IsRegular() {
		return ErrInboxPerms
	}
	if runtime.GOOS != "windows" {
		if fi.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("%w (mode %04o)", ErrInboxPerms, fi.Mode().Perm())
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			if int(st.Uid) != os.Getuid() {
				return fmt.Errorf("%w (wrong owner)", ErrInboxPerms)
			}
			if st.Nlink > 1 {
				return fmt.Errorf("%w (hardlinked, nlink=%d)", ErrInboxPerms, st.Nlink)
			}
		}
	}
	return nil
}

// assertInboxDir requires <support>/build-requests to be a real directory (not a symlink), owned by
// this user with mode 0700 (QA v2 L1).
func assertInboxDir(supportDir string) error {
	dir := InboxDir(supportDir)
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: inbox directory must not be a symlink", ErrInboxEscape)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: inbox is not a directory", ErrInboxPerms)
	}
	if runtime.GOOS != "windows" {
		if fi.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("%w: inbox directory must be mode 0700 (mode %04o)", ErrInboxPerms, fi.Mode().Perm())
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
			return fmt.Errorf("%w: inbox directory wrong owner", ErrInboxPerms)
		}
	}
	return nil
}

// MarshalPreview is a test helper.
func MarshalPreview(p Preview) []byte {
	b, _ := json.Marshal(p)
	return b
}
