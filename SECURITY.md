# Security Model

Skyport binds to loopback and requires authentication for every `/api` and
`/v1` request. The control plane and inference API use separate 256-bit tokens.
Raw tokens are stored in platform-secure credential storage; `config.toml`
contains only SHA-256 verifiers. Windows, macOS, and desktop Linux use their
native operating-system keyring. Android/Termux stores secrets as separate
atomic files under `~/.skyport/credentials`, inside Termux's app-private home,
with `0700` directory and `0600` file permissions enforced on every access.

Retrieve tokens only when needed:

```text
skyport auth show admin
skyport auth show inference
```

Rotate a token if it may have been exposed:

```text
skyport auth rotate admin
skyport auth rotate inference
```

Provider keys and OAuth tokens are stored in `~/.skyport/vault.json` using a
versioned AES-256-GCM envelope. The random master key is stored separately in
the platform credential store. Rotate it with `skyport keys rotate-master`.

`skyport keys add PROVIDER ALIAS` and `skyport keys replace ALIAS` read secrets
from a hidden terminal prompt. Secrets are never accepted as command-line
arguments.

Credential-bearing providers must use HTTPS. Redirects, credentialed URLs,
private or reserved destinations, and unsafe model path segments are rejected.
The built-in Ollama and LM Studio providers are the only keyless HTTP loopback
exceptions.

Workspace tools are restricted to the configured canonical workspace. Diffs
and repository facts are bounded and redacted before model use. Cloud utility
models require explicit `utility.allow_cloud` consent.

The SQLite database contains request metadata such as provider, model, key
alias, token counts, latency, and estimated cost. It also contains the fetched
NVIDIA skill catalog and global enable state, but not the downloaded skill
files. It does not contain prompts, responses, provider keys, OAuth tokens, or
gateway tokens. The entire database is encrypted at rest with SQLCipher; its
random 256-bit key is stored in the platform credential store. Existing
plaintext databases are migrated automatically.
Full-disk encryption remains recommended to protect swap, temporary files, and
disk sectors left by data written before migration.

Enabling a catalog skill invokes the pinned `skills` CLI through `npx` and
installs that skill globally for all supported agents. The source repository,
skill name, CLI package, and command flags are fixed by Skyport; arbitrary
commands and repository URLs are not accepted. Disabling removes the global
skill links and canonical files. These operations require an authenticated
admin API request and may write to supported agents' global skill directories.

Application encryption cannot protect secrets from malware or debuggers
already running as the same OS user. Keep crash dumps and swap/page files
protected and rotate upstream credentials after a suspected host compromise.
