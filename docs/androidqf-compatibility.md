# AndroidQF compatibility decision

Verified on 2026-11-15 against the official Windows v1.8.3 release and its tagged
source. **The official release stays blocked:** it cannot enforce the approved
non-interactive scope and encrypted workspace contract.

**Update 2026-11-15 (owner decision, collector#2):** Collector approves exactly one
build compiled from upstream `main` at commit
`05811f3c6f1df58ad633f2f6c47598cab994dd57` (7 Nov 2026, not yet released). See
[Approved build](#approved-build). The sections below the approved-build section
describe the v1.8.3 findings that led to it.

## Approved build

Upstream `main` at `05811f3c6` closes the v1.8.3 gaps that matter to Collector:

| v1.8.3 gap | `main` at `05811f3c6` | Collector |
|---|---|---|
| No `-non-interactive` | `-non-interactive` fails instead of prompting and skips the final Enter | Always passed |
| No scope flags | `-backup`, `-download`, `-remove-trusted`, `-intrusion-logs`, `-hash-files`, `-browser-history`, `-magisk-modules` | Mapped from the job scope (`build_args`) |
| Output in the executable folder | `-output` is honoured (`NewStreamingZipWriter`) | `-output <job>\output` |
| No `-key` | `key.txt` is read from the working directory first, then the executable folder (`acquisition/key.go`) | Writes the Ingest recipient to `<job>\key.txt` (exclusive create) and runs with cwd = job folder; refuses to start if `key.txt` exists beside the exe |
| Plaintext fallback | Without `key.txt` the archive is plaintext; an unreadable or invalid `key.txt` is an error | The recipient file is always present; `pack.adopt_archive` accepts only one `*.zip.age` with an age header, anything else fails the job (`UNEXPECTED_ARTIFACT`) |
| Module status | Still inside the ciphertext | Unchanged: `pending_verification` until the server decrypts |

Approval is the pair (SHA-256, version string) in `APPROVED_BUILDS` in
`src/astria_collector/androidqf.py`. Help text never approves a binary, and
changing the configured checksum cannot approve another one. `Manifest.androidqf_version`
and Ingest's `CollectorConfig` still carry the release line `1.8.3`; the exact
build is identified by `androidqf_sha256` in the manifest.

### Reproducible build

On Windows with Go 1.27.3 (fetched by `GOTOOLCHAIN=auto` from `go.mod`):

```sh
git clone https://github.com/mvt-project/androidqf.git && cd androidqf
git checkout 05811f3c6f1df58ad633f2f6c47598cab994dd57
export GOTOOLCHAIN=auto GOFLAGS=-trimpath CGO_ENABLED=0
(cd android-collector &&
 GOOS=linux GOARCH=arm GOARM=6 go build -ldflags="-s -w -buildid=" -o ../assets/collector_arm . &&
 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w -buildid=" -o ../assets/collector_arm64 . &&
 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -buildid=" -o ../assets/collector_amd64 .)
cp <platform-tools>/adb.exe <platform-tools>/AdbWinApi.dll <platform-tools>/AdbWinUsbApi.dll assets/
GOOS=windows GOARCH=amd64 go build \
  -ldflags="-s -w -buildid= -X github.com/mvt-project/androidqf/utils.Version=v1.8.3-95-g05811f3" \
  -o build/androidqf_windows_amd64.exe .
```

The embedded adb is Google platform-tools 37.0.1 (`adb version` 1.0.41):
`adb.exe` `b4a6b455702684652cccf7b46258b29e653538904359a58fd4931cf3ef286b3f`,
`AdbWinApi.dll` `c1d653030b4bde65d3e07e4d0b0979e17be56df1436cdd15528630f27808050d`,
`AdbWinUsbApi.dll` `0710e894d9b40f71a670c13c694079d564c92c1279da382cfe4850983aaebe1b`.
A different adb changes the executable digest and the build is no longer approved.

Upstream CI builds Windows with CGO and mingw; this build uses `CGO_ENABLED=0`
(no package in the tree imports `C`).

## Evidence

The [v1.8.3 release](https://github.com/mvt-project/androidqf/releases/tag/v1.8.3)
points to commit `472203c2395f7b07502d1f16b22a4d2900e35dda`. Its Windows asset is
`androidqf_windows_amd64_1.8.3_unsigned.exe` (10,819,072 bytes), SHA-256
`2a5aa89b8aa2145d1246372ef3310ffd1e6d8a457c59b0a232c3de79892d4650`.
The release's `checksums.txt` lists that same hash under a filename without the
`_unsigned` suffix. The downloaded asset hash matched both the checksum file and
GitHub's release asset digest.

Only `androidqf.exe -version` and `androidqf.exe -h` were executed. Both exited 0;
the version reported `1.8.3`. The binary was downloaded under the workspace's
ignored `resource/2026-11-15-astria-collector-implementasi/upstream/` directory for these probes. It is
not included in the operator distribution. No acquisition or phone command was run.

The [tagged command-line entry point](https://github.com/mvt-project/androidqf/blob/472203c2395f7b07502d1f16b22a4d2900e35dda/main.go)
agrees with the executable help: it has `-serial` and `-output`, but lacks
`-non-interactive` and all seven requested scope flags. It also lacks `-key`.
It calls interactive modules and a final Enter prompt. Scope options visible on
the repository's current development branch are not evidence for this release.

## Differences from the design

| Design assumption | Verified v1.8.3 behavior | Collector response |
|---|---|---|
| Complete unattended scope flags | Required options absent | Reject before acquisition |
| `-key` selects a recipient | No such option | Never send an invented flag |
| Working directory contains encrypted output | Key and ciphertext use the executable directory | No production adapter approved |
| Encryption failure cannot leave plaintext | Encryption initialization can fall back to normal storage | Block unsafe release |
| Read module status from adjacent `acquisition.json` | Metadata is inside ciphertext; tagged schema has no module statuses | Preserve unknown status until server validation |
| A zero process exit proves complete collection | Module errors are logged while execution continues | Never equate exit 0 with verified scope |

The [encrypted stream implementation](https://github.com/mvt-project/androidqf/blob/472203c2395f7b07502d1f16b22a4d2900e35dda/acquisition/encrypted_stream.go)
uses the executable directory for both `key.txt` and `<UUID>.zip.age`, independently
of the supplied output folder. The [acquisition implementation](https://github.com/mvt-project/androidqf/blob/472203c2395f7b07502d1f16b22a4d2900e35dda/acquisition/acquisition.go)
falls back to ordinary storage if encrypted initialization fails. On successful
streaming, it places metadata and command logs inside the encrypted archive.
Collector does not decrypt evidence or infer per-module results from console text.

## Where the gate runs

The gate runs at three points, all before a phone is touched:

1. `astria-collector check` reports the verdict and exits 1.
2. The console runs a preflight when a job is opened, before it asks for the job ID and before it
   shows any USB steps. The job is **not** reported `gagal` to Ingest, so a local tool problem does
   not consume the consent; the job stays available once the installation is fixed.
3. `Runner.execute` repeats the preflight, then re-verifies both tool hashes, then waits for the device.

Verified on 2026-11-15 with the frozen Windows executable, the official v1.8.3 binary (hash matched),
real `adb` 1.0.41, and a live Ingest job: the job was fetched and shown, the preflight refused it with
`TOOL_INCOMPATIBLE`, and no work folder was created.

## Gate and resolution

The operator may configure the official binary and expected hash to diagnose
installation. `inspect_tool` verifies the hash before help/version execution,
bounds process output and time, and rechecks the binary afterward. Acquisition
then fails with `TOOL_INCOMPATIBLE`. A binary advertising the missing flags still
fails with `TOOL_PROFILE_UNAPPROVED`; help text is not an encryption guarantee.
There is no operator switch to bypass this gate.

The scope-to-argument helper and synthetic tests exercise the proposed contract,
not compatibility with the release. A reviewed upstream release or explicitly
approved fork must supply unattended scope enforcement, an encryption-required
mode, controlled key/output paths, and documented acquisition result semantics.
That requires a new pinned digest, code review, regression tests, and authorized
physical-device validation before enabling production acquisition. Do not claim
the issue Done or automatically substitute a development build.
