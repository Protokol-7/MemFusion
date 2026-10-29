# Manual patches applied to vendored plugins

`scripts/patch_plugins_for_vol3.py` handles the mechanical Volatility 3 API
migration (dependency versions, and `layer_name`+`symbol_table` →
`kernel_module_name` at call sites). These changes are **not** mechanical and
must be re-applied by hand if a plugin is ever re-copied from upstream.

They are listed here because that has already happened once: re-deriving the
vendored files from their pristine clones silently reverted every one of them,
and the resulting breakage looked like new bugs.

| File | Change | Why |
|---|---|---|
| `keepass.py` | `--pid` requirement made `optional=True`; `run()` falls back to `PsList.create_name_filter(["KeePass.exe", "keepass.exe"])` | Upstream requires a PID argument, which this GUI does not pass — the plugin would fail on every run. |
| `windows/dumpcerts.py` | `from …asymmetric.types import PrivateKeyTypes as PRIVATE_KEY_TYPES` | `cryptography` ≥40 renamed `PRIVATE_KEY_TYPES`. Without the alias **both** `dumpcerts` *and* `symcrypt` (which imports it) fail to load. |
| `linux/bpf_*.py`, `linux/bpfutil/` | All `volatility3.utility.*` imports rewritten to `volatility3.plugins.linux.bpfutil.*` | Upstream BPFVol3 expects a package injected into the vol3 install plus a source patch; see the BPFVol3 section in README.md. |

## Known-unfixable without a real port

| Plugin | Problem |
|---|---|
| `windows/autorun.py` | Uses the pre-3.x requirement style (`TranslationLayerRequirement('primary')` + `SymbolTableRequirement('nt_symbols')`) instead of a `ModuleRequirement('kernel')`, so `self.config["kernel"]` raises `KeyError`. Porting means migrating its requirements and every use of `self.config['primary']`/`['nt_symbols']` throughout the file. |
| `openssh_sessionkeys.py` | Needs a hand-built `openssh64` ISF symbol file for the target sshd binary. |
| `windows/directsyscalls.py` | Its own `list_injections()` classmethod takes `(context, kernel_layer_name, symbol_table, proc)`; adapting it is a classmethod signature change, not yet done. |

These are excluded from the recommended set so they are not run by default.
