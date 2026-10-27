# RottenCore PR #1 QA attack report

**Verdict: MERGE**

| | |
|---|---|
| PR | https://github.com/grimvirusoffical-source/RottenCore/pull/1 |
| Head | `fe813b7ac54c86b500ea119044117180d7126502` |
| Branch | `cursor/lifetime-cert-sign-0e14` |
| Host | Linux VM, Go 1.22.2, `red-xai-encrypt` 0.3.0 on `PATH` |
| Product sources | Not modified. Attack harness is `core/qa_attack_test.go` (`//go:build qa` only). |
| Merge performed | No |

Upstream CI for this head (run 40450362996): `engine` pass, `macos` pass, `release` skipped (not a tag). This VM did not re-run the macOS job and did not exercise the Mac GUI.

## Closed

| Focus | Result | What was proven on this VM |
|---|---|---|
| 1. Owner unlock is the owner path only | CLOSED | Both owner addresses, case-folded and trimmed, unlock and sign. Missing verified, `idVerified`, or second factor refuses. A string `"true"` for `idVerified` refuses. `idVerified: false` on userinfo stays false when the account document says true. Second-factor claims that exist only on the account document do not count. An owner email that is not on `owner_emails` is shown as a profile owner by `WhoAmI` and still cannot `SignLifetime` or `RunAgent`. An email that is not one of the two owner addresses refuses even if `owner_emails` lists it, including a decoy owner email on the account document. Look-alike, plus-address, and truncated domains refuse. Every non-owner trial was given lifetime ciphertext; the lifetime decrypt counter stayed at zero, no carrier was written, and the error text did not carry private material. |
| 2. Developer cannot sign without the launcher | CLOSED | With no launcher binary and `ROTTENCORE_RA_LAUNCHER` unset, `SignDeveloper` and agent sign refuse and write no carrier. `SignLifetime` refuses a developer token even when ciphertext is attached. After an owner unlock, agent sign with `withLauncher: false`, an empty token, and a request that adds an unknown key field all refuse, and the error does not echo that field. Agent sign while the launcher is down refuses. With the launcher up, a developer signature (owner cert through the agent, and the developer’s own key) has `launcher_required` set and the Linux host still refuses `ios`. CLI `sign --developer --without-launcher` exits 2. After agent shutdown, further agent sign returns the agent-down error. Setting `ROTTENCORE_RA_LAUNCHER` only chooses which executable counts as the launcher; it still cannot clear `launcher_required` for a developer. |
| 3. `open` installs sealed apps and refuses unsigned / unsealed payloads | CLOSED | A developer-sealed zip installs through `OpenSigned` when the not-trusted warning is accepted, with both the test sealer and real `red-xai-encrypt` 0.3.0. The same sealed zip is not installed when the warning is not accepted (`ErrUntrusted`). Refused, with nothing installed: no carrier, raw JSON in a `.rotten_core_signed` file, a non-image `.Red_SecretXAI`, a flipped artifact byte, a flipped carrier byte, a sealed payload from a key this computer did not mint, and a wrong password. CLI `open --accept-untrusted --secrets-stdin` on an unsigned zip exits non-zero with the not-signed class, and the password is not on the process command line. |
| 4. Carriers and release artifacts contain no private key material | CLOSED | The git tree has no `.dmg`, `.pkg`, `.pem`, `.p12`, `.Red_SecretXAI`, `.rotten_core_signed`, `dist/`, or `build/` artifacts. The text `private_enc` appears as a field name in source, docs, and tests, not as a checked-in ciphertext blob. No PEM armor is in the tree. Carriers, red-X outputs, and support files produced during the real-sealer run were scanned for the generated private-key bytes, that key’s hex, the password, PEM armor, and the `private_enc` field. None were present. The developer keyring value did not contain those in the clear. The decrypted developer private key was not in the carrier or `developer-certs.json` (mode `0600`). Sign temp files were removed. |
| 5. Daemon, login, and dev-cert stay inside the ownership gates and do not expose private material | CLOSED | The daemon records carrier names, does not copy carrier bytes, does not install, and resets without deleting installed state. `dev-cert` for a non-owner does not decrypt the lifetime ciphertext. Its result and `developer-certs.json` have public fields only. Quick Login with `remember_device` false does not store access or refresh tokens. A verification URI made of shell metacharacters is passed through unchanged and is not executed. The Linux autostart unit contains no private material. The agent socket is mode `0600` and its directory is not group-accessible. A pre-created mode `0777` short-socket directory is refused and no agent stays up. |

## Open

No focus item is open.

## Suite counts

`gofmt -l` clean. `go vet ./...` clean.

Product suite, tag-free, `red-xai-encrypt` 0.3.0 present so the live text and PNG round trips ran (0 skips):

| Command | Packages | Tests |
|---|---|---|
| `go test -count=1 ./...` | 3 pass (`cmd/rottencore` 1, `core` 34, `internal/sign` 8) | 43 pass, 0 fail, 0 skip |
| `go test -race -count=1 ./...` | 3 pass, same split | 43 pass, 0 fail, 0 skip |

QA harness (not part of the 43):

| Command | Tests |
|---|---|
| `go test -tags qa -count=1 -run TestQA ./core/` | 8 pass, 0 fail, 0 skip |
| `go test -tags qa -race -count=1 -run TestQA ./core/` | 8 pass, 0 fail, 0 skip |

The eight QA tests are `TestQAOwnerUnlockOnly`, `TestQADeveloperCannotSignWithoutLauncher`, `TestQAOpenSealedRefusesUnsigned`, `TestQADaemonLoginDevCert`, `TestQAAgentRejectsLooseSocketDir`, `TestQASchemeAndPathSmoke`, `TestQARealSealerCarrier`, and `TestQACLIGates`.

## Path and scheme smoke

PR-touched checks that were executed here:

- `ValidOrigin` and bearer fetch refuse `file:`, `javascript:`, non-loopback `http`, and userinfo in the URL. `https` origins still pass.
- `LoadConfig` refuses a `file`, `javascript`, or non-loopback `http` accounts issuer.
- Manifest validation refuses `install.bundle`, `install.pkg`, and GitHub asset names that contain a slash or `..`.

`LoginQuick` does not shell out. `openBrowser` in `cmd/rottencore/session.go` is `exec.Command` with the URI as one argument (`xdg-open` on Linux). That helper was not pointed at a live browser in this run.

`core/engine.go` and `core/fake_test.go` are not in this PR. Production unzip calls `/usr/bin/ditto`. `ditto` is not installed on this VM, so the production extractor was not executed. The test double’s unzip joins a `../` entry and can write outside its temp directory. That double is not linked into `rottencore`. It is not scored as an open focus item. Unsigned `open` never reaches extract.

## Mac-deferred

Not run on this Linux VM. Do not read any of these as a pass.

- Mac app GUI: Unlock, Sign with launcher, Sign without launcher, Quick Login, sign-out.
- Swift tests for palette, `SignGate`, handshake frames, and `SignResult` / `SessionAck` decode.
- `ditto` copy into `/Applications` or `~/Applications`, disk images, and packages.
- Real macOS Keychain (`Security.framework`). The keyring argv test on this VM fakes `secret-tool`.
- `launchd` load of the daemon plist. Linux autostart text was checked only.
- `ps -axww` launcher scan. This VM used `/proc`.
- Darwin unix-socket length on a Mac temp directory. The overlong support path was checked on Linux and landed on a private short socket under `/tmp`.
