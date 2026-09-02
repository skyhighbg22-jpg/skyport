# Skyport — Local-first Universal AI Gateway

Local-first proxy and control plane that sits between your tools and AI providers. Telemetry, cost tracking, and global skills — all on `127.0.0.1`.

![version](https://img.shields.io/badge/version-0.1.2-blue) ![license](https://img.shields.io/badge/license-MIT-green)

## Features

- **Universal proxy** — OpenAI-compatible `/v1/*` for any provider (OpenAI, Anthropic, Gemini, Groq, DeepSeek, Ollama, LM Studio, …)
- **Secure by default** — Loopback-only, separate `admin` + `inference` 256-bit tokens in OS keyring, SHA-256 verifiers on disk
- **Encrypted vault** — Provider keys & OAuth tokens in AES-256-GCM `vault.json`, master key in keyring
- **Telemetry** — Token counts, latency, cost, and request log in SQLCipher-encrypted SQLite
- **Skills** — One-click enable/disable of all 341 official [NVIDIA/skills](https://github.com/NVIDIA/skills) + custom `npx skills` packages, installed globally for every supported agent
- **Web dashboard** — Single-file `static/index.html` embedded in the binary
- **Verified releases** — Every downloaded binary is checked against the release's SHA-256 manifest before installation

## Install

Prebuilt binaries are available from [GitHub Releases](https://github.com/skyhighbg22-jpg/skyport/releases). The installers download the correct binary for your machine and verify its SHA-256 checksum.

**macOS / Linux**

```bash
curl -fsSL https://raw.githubusercontent.com/skyhighbg22-jpg/skyport/main/install.sh | sh
```

**Windows PowerShell**

```powershell
irm https://raw.githubusercontent.com/skyhighbg22-jpg/skyport/main/install.ps1 | iex
```

No Rust toolchain is needed for either installer.

**From source**

Requires Rust 1.86 or newer, a C/C++ build toolchain, and Perl (used to compile
the vendored OpenSSL dependency). Linux builds bundle the D-Bus client library,
so distribution-specific `libdbus` development packages are not required.

```bash
git clone https://github.com/skyhighbg22-jpg/skyport.git
cd skyport
cargo build --locked --release
```

You can also install directly from Git:

```bash
cargo install --locked --git https://github.com/skyhighbg22-jpg/skyport.git
```

## Quick start

```bash
skyport serve
```

Flow:

```
Authenticate and launch Skyport gateway with access control? [y/N]: y
Authentication verified. Gateway running with secure access control.
Need the admin token right now? [y/N]: y

Admin token (paste into dashboard):
<token>

Dashboard: http://localhost:5790
```

Paste the token into the dashboard's **Admin bearer token** field. It lives only in page memory.

> Already running? `skyport auth show admin` prints the token anytime — no second terminal needed. `skyport serve -y` skips both prompts.

## Dashboard

`http://localhost:5790` — Traffic, Playground, Providers, Keys, Skills, and more. The `Skills` tab (10) lazily fetches the NVIDIA catalog on first open; nothing is downloaded until you toggle a skill on.

## CLI

```bash
skyport serve [--yes] [--no-open]   # start gateway + dashboard
skyport ui                          # open dashboard in browser
skyport auth show admin|inference   # print token
skyport auth rotate admin|inference # rotate token (restart required)
skyport keys add PROVIDER ALIAS     # add provider key (hidden prompt)
skyport keys list | remove ALIAS | rotate-master
skyport status | stop
skyport providers                   # test credentials / discover models
```

Inference clients use `Authorization: Bearer <inference-token>` against `http://127.0.0.1:5790/v1/*`.

`GET /healthz` is intentionally unauthenticated on loopback and identifies the running Skyport version and PID. The `status`, `ui`, and `stop` commands use it to verify they are talking to the real gateway—even after a configured port change.

## Skills

- Catalog is fetched from `NVIDIA/skills` on demand and cached in `~/.skyport/skyport.db` (encrypted).
- Toggling a skill runs the pinned `skills@1.5.23` CLI via `npx`:
  - enable: `npx --yes skills@1.5.23 add NVIDIA/skills --skill <name> --agent * --global --yes`
  - disable: `npx --yes skills@1.5.23 remove --global --agent * --yes <name>`
- Custom skills: dashboard → Skills → Import (`npx skills add <source>`). Requires Node.js + `npx`.
- Skill content is CC BY 4.0, source code Apache 2.0 — see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Security

See [SECURITY.md](SECURITY.md). Highlights: HTTPS required for credentialed providers, private/reserved destinations blocked, workspace tools sandboxed, diffs bounded and redacted, cloud utilities opt-in.

## Development

```bash
cargo fmt --check
cargo test --locked # 100 Rust tests
cargo clippy --all-targets --all-features -- -A clippy::collapsible-if -A clippy::too-many-arguments -A clippy::redundant-locals -D warnings
cargo build --release
npm test            # installer target and checksum parsing
```

## License

MIT — see [LICENSE](LICENSE).
