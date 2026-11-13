# Third-party notices

This package vendors the following MIT-licensed components under `assets/wasm/` so the
plugin can parse shell syntax in-process without spawning a parser process or downloading
anything at runtime.

| Component | Version | License | Vendored files |
|---|---|---|---|
| web-tree-sitter | 0.25.10 | MIT | `tree-sitter.js`, `tree-sitter.wasm`, `LICENSE-web-tree-sitter` |
| tree-sitter-bash | 0.25.1 | MIT | `tree-sitter-bash.wasm`, `LICENSE-tree-sitter-bash` |
| tree-sitter-powershell | 0.26.6 | MIT | `tree-sitter-powershell.wasm`, `LICENSE-tree-sitter-powershell` |

Sources: npm registry (`https://registry.npmjs.org/...`), retrieved 2026-11-08. Files are
byte-for-byte copies of the published artifacts, pinned by the SHA-256 values below.

| File | SHA-256 |
|---|---|
| `tree-sitter.js` | `d4fc466df6358055253bc4cdaab23cdf84fe00741fa5a4ff56506c06c533da42` |
| `tree-sitter.wasm` | `f38dcc4b43b818f9a0785bc1c6d5611a75ac4cdd428ff3f02757c34ca4e46d7f` |
| `tree-sitter-bash.wasm` | `8292919c88a0f7d3fb31d0cd0253ca5a9531bc1ede82b0537f2c63dd8abe6a7a` |
| `tree-sitter-powershell.wasm` | `9b95cfc95825e2c0a8f764bfeb030318c8a258165f41c413585e29ee3b6c1e19` |

The full MIT texts are in `LICENSE-web-tree-sitter`, `LICENSE-tree-sitter-bash`, and
`LICENSE-tree-sitter-powershell` in the same directory.
