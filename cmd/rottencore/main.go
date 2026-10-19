// Command rottencore is the RottenCore command line: the same engine as the RottenCore Installer app.
//
//	rottencore inspect <file>                            what is it, where is it from, is it trusted
//	rottencore install <file | github:owner/repo[@tag] | store:<app id>> [--accept-untrusted] [--user]
//	rottencore list | check-updates | update <app id> | uninstall <app id>
//	rottencore search <words> | info <app id>            the Rotten Apple store catalog (optional)
//	rottencore config [--store-url URL] [--accounts-issuer URL] [--theme dark|light|system]
//	rottencore signin                                    Red-XAI Accounts (coming soon)
//
// Every command takes --json (one JSON object on stdout: {"ok":true,"result":...} or {"ok":false,"error":...,"code":...}).
// Exit codes: 0 ok, 1 error, 2 usage, 3 untrusted (accept the warning to continue), 4 refused (checksum mismatch).
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/grimvirusoffical-source/RottenCore/core"
)

type opts struct {
	json, accept, user, yes bool
	admin                   string
}

var o opts

// cleanups run before every exit (os.Exit skips defers): a disk image must never stay mounted.
var cleanups []func()

func onExit(f func()) { cleanups = append(cleanups, f) }

func runCleanups() {
	for i := len(cleanups) - 1; i >= 0; i-- {
		cleanups[i]()
	}
	cleanups = nil
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		usage()
		os.Exit(2)
	}
	cmd := args[0]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	fs.BoolVar(&o.json, "json", false, "print one JSON object")
	fs.BoolVar(&o.accept, "accept-untrusted", false, "accept: "+core.UntrustedWarning)
	fs.BoolVar(&o.user, "user", false, "install into ~/Applications instead of /Applications")
	fs.BoolVar(&o.yes, "yes", false, "do not ask before installing (trusted apps only; untrusted ones still need --accept-untrusted)")
	fs.StringVar(&o.admin, "admin", "sudo", "how to ask for the administrator password: sudo | osascript")
	storeURL := fs.String("store-url", "", "config: Rotten Apple store API origin")
	issuer := fs.String("accounts-issuer", "", "config: Red-XAI Accounts OIDC issuer")
	theme := fs.String("theme", "", "config: dark | light | system")
	limit := fs.Int("limit", 25, "search: at most this many results")
	fs.StringVar(&progressMode, "progress", "", "fetch: progress as json (NDJSON on stderr) for the loading screen")
	fs.StringVar(&testRootHex, "trust-test-root", "", "trust a TEST Red-XAI CA root (hex) for this run; results are labelled TEST")
	kid := fs.String("kid", "", "verify-update-manifest: X-RedX-Key-Id")
	lastSeq := fs.Int64("last-seq", 0, "verify-update-manifest: last applied sequence for the app")
	fs.StringVar(&signKey, "key", "", "sign/build: developer private key file (rottencore-ca keygen); mutually exclusive with --keychain")
	fs.BoolVar(&signKeychain, "keychain", false, "sign/build: load the developer key from the macOS Keychain (Josh's Mac); never writes a key file")
	fs.StringVar(&signLabel, "label", "", "sign/build: Keychain account / label (e.g. josh-mega); required with --keychain")
	fs.StringVar(&signService, "service", "", "sign/build: Keychain service (default com.redx.rottencore.ca)")
	fs.StringVar(&signBundle, "bundle", "", "sign/build: developer certificate bundle (rottencore-ca issue)")
	fs.StringVar(&signApp, "app", "", "sign: reverse-DNS app id recorded in the .rasig")
	fs.StringVar(&signVersion, "app-version", "", "sign: version recorded in the .rasig")
	fs.StringVar(&signPlatform, "platform", "", "sign: target platform (inferred from the file name when omitted)")
	fs.StringVar(&signHost, "sign-host", "", "sign/build: override the signing device OS (darwin|windows|linux); defaults to this machine")
	fs.StringVar(&buildOut, "out", "", "build: output directory")
	fs.StringVar(&devTeam, "team", "", "device approve: team id (omit with --individual)")
	fs.BoolVar(&devIndividual, "individual", false, "device approve: approve under an individual account")
	fs.Parse(reorder(args[1:]))
	rest := fs.Args()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	defer runCleanups()
	dir := core.SupportDir()
	if cmd == "version" {
		out(map[string]string{"version": core.Version}, func() { fmt.Println("rottencore", core.Version) })
		return
	}
	if cmd == "pkg-remove" { // root step of uninstall (started through the admin prompt)
		need(rest, 1)
		if os.Geteuid() != 0 {
			fail(errors.New("pkg-remove must run as root"), 1)
		}
		e := &core.Engine{R: &core.ExecRunner{}}
		removed, err := e.RemovePkg(ctx, rest[0])
		check(err)
		out(map[string]interface{}{"removed": len(removed)}, func() { fmt.Printf("removed %d files of %s\n", len(removed), rest[0]) })
		return
	}
	if runM1(ctx, cmd, rest, *kid, *lastSeq) {
		return
	}
	if runDevice(ctx, cmd, rest) {
		return
	}
	if runSign(ctx, cmd, rest) {
		return
	}
	if cmd == "config" {
		cfg, err := core.LoadConfig(dir)
		check(err)
		if *storeURL != "" {
			cfg.StoreURL = *storeURL
		}
		if *issuer != "" {
			cfg.AccountsIssuer = *issuer
		}
		if *theme != "" {
			if *theme != "dark" && *theme != "light" && *theme != "system" {
				fail(errors.New("theme must be dark, light or system"), 2)
			}
			cfg.Theme = *theme
		}
		if *storeURL != "" || *issuer != "" || *theme != "" {
			check(core.SaveConfig(dir, cfg))
			_, err := core.LoadConfig(dir) // validates
			check(err)
		}
		out(cfg, func() { b, _ := json.MarshalIndent(cfg, "", "  "); fmt.Println(string(b)) })
		return
	}
	c, err := core.NewCore(dir, o.admin)
	check(err)
	if testRootHex != "" {
		pol := chainPolicy()
		c.Roots, c.Production = pol.Roots, false
	}
	dest := ""
	if o.user {
		dest = "~/Applications"
	}
	switch cmd {
	case "inspect":
		need(rest, 1)
		in, err := c.Inspect(ctx, rest[0], nil)
		check(err)
		onExit(in.Close)
		out(in, func() { printInspection(in) })
	case "install":
		need(rest, 1)
		target := rest[0]
		var in *core.Inspection
		switch {
		case strings.HasPrefix(target, "store:"):
			link, err := core.StoreInstallLink(c.StoreURL, strings.TrimPrefix(target, "store:"))
			check(err)
			// The Rotten Apple launcher shows its own install sheet and does every store check.
			if _, err := exec.Command("/usr/bin/open", link).CombinedOutput(); err != nil {
				fail(fmt.Errorf("could not hand %s to the Rotten Apple launcher: %w", link, err), 1)
			}
			out(map[string]string{"handedTo": "ra-launcher", "link": link}, func() { fmt.Println("opened in the Rotten Apple launcher:", link) })
			return
		case strings.HasPrefix(target, "github:"):
			repo, tag, _ := strings.Cut(strings.TrimPrefix(target, "github:"), "@")
			owner, name, ok := strings.Cut(repo, "/")
			if !ok {
				fail(errors.New("use github:owner/repo or github:owner/repo@tag"), 2)
			}
			in, err = c.FetchGitHub(ctx, owner, name, tag, "", "", progress())
		default:
			in, err = c.Inspect(ctx, target, nil)
		}
		check(err)
		onExit(in.Close)
		install(ctx, c, in, dest)
	case "list":
		l, err := c.State.List()
		check(err)
		out(l, func() {
			if len(l) == 0 {
				fmt.Println("nothing installed by RottenCore")
			}
			for _, e := range l {
				t := "untrusted (accepted)"
				if e.Trusted {
					t = "Rotten Apple store"
				}
				fmt.Printf("%-32s %-12s %-7s %-6s %s\n", e.AppID, e.Version, e.Source, e.Kind, t)
			}
		})
	case "check-updates":
		u, err := c.CheckUpdates(ctx)
		check(err)
		out(u, func() {
			for _, x := range u {
				switch {
				case x.Error != "":
					fmt.Printf("%-32s %s: %s\n", x.AppID, x.Installed, x.Error)
				case x.Newer:
					fmt.Printf("%-32s %s -> %s\n", x.AppID, x.Installed, x.Available)
				default:
					fmt.Printf("%-32s %s (up to date)\n", x.AppID, x.Installed)
				}
			}
		})
	case "update":
		need(rest, 1)
		e, err := c.State.Get(rest[0])
		check(err)
		if e == nil {
			fail(core.ErrNotInstalled, 1)
		}
		if e.Managed == "ra-launcher" {
			check(c.UpdateViaLauncher(ctx, e))
			out(map[string]string{"updatedBy": "ra-launcher"}, func() { fmt.Println("updated by the Rotten Apple launcher") })
			return
		}
		in, err := c.PrepareUpdate(ctx, rest[0], progress())
		check(err)
		onExit(in.Close)
		if CompareVersionsOK(in.Version, e.Version) {
			install(ctx, c, in, "")
		} else {
			out(map[string]string{"installed": e.Version, "available": in.Version}, func() { fmt.Println(e.AppID, "is up to date at", e.Version) })
		}
	case "uninstall":
		need(rest, 1)
		e, err := c.Uninstall(ctx, rest[0])
		check(err)
		out(e, func() { fmt.Println("uninstalled", e.Name) })
	case "search":
		st := &core.Store{Origin: c.StoreURL, Net: c.Net}
		l, err := st.Search(ctx, strings.Join(rest, " "), *limit)
		check(err)
		out(l, func() {
			for _, x := range l {
				fmt.Printf("%-32s %-10s %-8s %s\n", x.AppID, x.Version, x.AgeRating, x.Name)
			}
		})
	case "info":
		need(rest, 1)
		l, err := (&core.Store{Origin: c.StoreURL, Net: c.Net}).Lookup(ctx, rest[0])
		check(err)
		out(l, func() {
			fmt.Printf("%s %s (%s)\nage rating: %s\n%s\n", l.Name, l.Version, l.AppID, l.AgeRating, l.Tagline)
		})
	case "signin":
		_, err := c.Accounts.SignIn(ctx)
		check(err)
	default:
		usage()
		os.Exit(2)
	}
}

// CompareVersionsOK is true when available is newer than installed.
func CompareVersionsOK(available, installed string) bool {
	return core.CompareVersions(available, installed) > 0
}

func install(ctx context.Context, c *core.Core, in *core.Inspection, dest string) {
	v := in.Verdict
	if v.Refuse {
		if !o.json {
			printInspection(in)
		}
		fail(core.ErrRefused, 4)
	}
	if !v.Trusted && !o.accept {
		if !o.json {
			printInspection(in)
			fmt.Fprintln(os.Stderr, "\n"+core.UntrustedWarning+"\nRun again with --accept-untrusted to install it anyway.")
		}
		fail(core.ErrUntrusted, 3)
	}
	if v.Trusted && !o.yes && !o.json {
		printInspection(in)
		fmt.Print("Install? [y/N] ")
		s, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(s)), "y") {
			fail(errors.New("cancelled"), 1)
		}
	}
	e, err := c.Install(ctx, in, core.InstallOptions{AcceptUntrusted: o.accept, Destination: dest})
	check(err)
	out(e, func() {
		fmt.Printf("installed %s %s", e.Name, e.Version)
		if len(e.Paths) > 0 {
			fmt.Printf(" at %s", e.Paths[0])
		}
		fmt.Println()
		if e.Codesign != nil && e.Codesign.Detail != "" {
			fmt.Println("code signature:", e.Codesign.Detail)
		}
	})
}

func printInspection(in *core.Inspection) {
	fmt.Printf("%s %s (%s), %s\n", in.Name, in.Version, firstNonEmpty(in.AppID, "no app id"), in.Kind)
	fmt.Printf("source: %s (from %s)\n", in.Source, strings.Join(in.DetectedBy, ", "))
	if in.AgeRating != "" {
		fmt.Println("age rating:", in.AgeRating)
	}
	fmt.Printf("sha256: %s  checksum: %s\n", firstNonEmpty(in.Verdict.SHA256, "-"), in.Verdict.Checksum)
	if in.Verdict.Trusted {
		fmt.Println("trusted: from the Rotten Apple store")
	} else {
		fmt.Println("NOT TRUSTED:", in.Verdict.Warning)
	}
	for _, r := range in.Verdict.Reasons {
		fmt.Println("  -", r)
	}
	for _, p := range in.Problems {
		fmt.Println("  !", p)
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func progress() func(int64, int64) {
	if o.json {
		return nil
	}
	last := int64(-1)
	return func(done, total int64) {
		if total > 0 {
			if p := done * 100 / total; p != last && p%10 == 0 {
				last = p
				fmt.Fprintf(os.Stderr, "\rdownloading %d%%", p)
				if p == 100 {
					fmt.Fprintln(os.Stderr)
				}
			}
		}
	}
}

// reorder lets flags come after positional arguments.
func reorder(a []string) []string {
	var flags, pos []string
	valued := map[string]bool{"--admin": true, "-admin": true, "--store-url": true, "-store-url": true, "--accounts-issuer": true, "-accounts-issuer": true, "--theme": true, "-theme": true, "--limit": true, "-limit": true, "--progress": true, "-progress": true, "--kid": true, "-kid": true, "--last-seq": true, "-last-seq": true, "--trust-test-root": true, "-trust-test-root": true, "--key": true, "-key": true, "--label": true, "-label": true, "--service": true, "-service": true, "--bundle": true, "-bundle": true, "--app": true, "-app": true, "--app-version": true, "-app-version": true, "--platform": true, "-platform": true, "--sign-host": true, "-sign-host": true, "--out": true, "-out": true, "--team": true, "-team": true}
	for i := 0; i < len(a); i++ {
		if strings.HasPrefix(a[i], "-") && a[i] != "-" {
			flags = append(flags, a[i])
			if valued[a[i]] && i+1 < len(a) {
				flags = append(flags, a[i+1])
				i++
			}
		} else {
			pos = append(pos, a[i])
		}
	}
	return append(flags, pos...)
}

func out(v interface{}, text func()) {
	if o.json {
		json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"ok": true, "result": v})
		return
	}
	text()
}

func check(err error) {
	if err == nil {
		return
	}
	code := 1
	switch {
	case errors.Is(err, core.ErrUntrusted):
		code = 3
	case errors.Is(err, core.ErrRefused):
		code = 4
	}
	fail(err, code)
}

func fail(err error, code int) {
	runCleanups()
	if o.json {
		name := map[int]string{1: "error", 2: "usage", 3: "untrusted", 4: "refused"}[code]
		json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"ok": false, "error": err.Error(), "code": name})
	} else {
		fmt.Fprintln(os.Stderr, "rottencore:", err)
	}
	os.Exit(code)
}

func need(a []string, n int) {
	if len(a) < n {
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: rottencore <command> [flags]
  inspect <file>
  install <file | github:owner/repo[@tag] | store:<app id>> [--accept-untrusted] [--user] [--yes]
  list | check-updates | update <app id> | uninstall <app id>
  search <words> | info <app id>
  config [--store-url URL] [--accounts-issuer URL] [--theme dark|light|system]
  fetch <https url> <dest> [--progress json]
  verify-signature <file> [<signature file>]       Red-XAI cert chain + revocation (exit 3 not trusted, 4 revoked)
  verify-update-manifest <manifest.json> <sig|ed25519:...> <keys.json> [--kid K] [--last-seq N]
  signin | version
flags: --json --admin sudo|osascript
`)
}
