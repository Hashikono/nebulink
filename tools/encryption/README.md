# NebuLink vaults

Turns the plaintext game (`src/nebulink_v1.8.9.html`) into a build where **typing the right thing is the key**.

```bash
npm install                         # once (javascript-obfuscator, pinned)
node build.mjs                      # src/nebulink_v1.8.9.html + gates.json -> dist/nebulink_v1.8.9_vaulted.html
node build.mjs --obfuscate=off      # readable debug build (also: low | medium (default) | high)
node build.mjs SRC.html gates.json OUT.html
node test/verify.cjs                 # 47 checks: gates, login, vaulted FS == original FS
node test/shell.cjs                  # 88 shell checks, run on plaintext AND vaulted builds (needs playwright)
```

## What is gated (gates.json)

| Gate | Key | Opens |
|---|---|---|
| login | `ip` + `user` + `pass` | the guest layer (home, motd, /var/observatory shell) |
| `eridanus` | the path component `eridanus` | the whole B68 tree |
| `.cache` | the path component `.cache` | the hidden audio folder |
| `error00.log` | the path component `error00.log` | the file the XOR strip points at |

Gates **nest**: the `.cache` and `error00.log` ciphertexts live *inside* the eridanus vault, so
they cannot even be attempted until `eridanus` is open. Add a gate = add a line to `gates.json`
(`parent` = directory that must already exist, `name` = the component the player has to type).

## Behaviour you will notice
* Before it is unlocked a gated name simply does not exist: `ls -a`, tab-completion and `cat` all say
  "No such file or directory". After the right name is typed once, it is mounted for the session.
* Names are exact-case (same as the original game, `cd ERIDANUS` never worked).
* Login steps are verified by decrypting tiny sealed probes, so the IP/user/password are not in the file.
* `gates.json` contains the secrets. **Do not ship it.**

## Honest limits
Keys come from low-entropy answers, so this stops *reading the source* and `ls -a`, not a determined
dictionary attack (PBKDF2 x250k slows every guess, nothing more). Raise `iterations` for more slowdown
at the cost of login latency. Needs WebCrypto + DecompressionStream (current Chrome/Edge/Firefox/Safari 16.4+),
opened from `file://` or `https://`.

## What changed in v1.8.7 / v1.8.8 (src/nebulink_v1.8.9.html)
`ls` takes `-a -A -l -h -1`, clusters like `-la`, several paths, `~`, `--help`; output is sorted (journals are chronological).
`cd ~`, `cd -`. `cat`/`less`/`more` take several files. `head`/`tail` take `-n N`, `-N`, several files, and count lines correctly.
`echo` expands quotes, `~`, `$USER/$HOME/$PWD` and `* ?` globs (`-n`, `-e`). `hexdump -C` matches the real layout.
`rm` has real flags, one clean error per operand, guest can only delete under /home/guest; **`rm -rf /*`** (or `rm -rf / --no-preserve-root`)
is the kernel-panic easter egg, `rm -rf *` is an ordinary delete. `chmod` validates and is silent on success.
New: `history`, `id`, `logout`, `command --help`, `help <cmd>`, Ctrl+L, Ctrl+C. The 1991-01-03 log's Morse line now spells MISOKNIGHT backwards.

v1.8.8: `.CACHE` -> `.cache` in two logs (the real folder name is lowercase and names are case-sensitive); log files `1990-01-03/05/09.log` renamed to `1991-01-...` to match their entries; the two out-of-order lines in the 1991-01-03 log are in timestamp order.

## v1.8.9: obfuscation, sealed easter egg, realistic timing
* **One-line script.** The build obfuscates the engine with `javascript-obfuscator` (names mangled, strings RC4'd through a string array,
  control-flow flattening/dead code at `medium`) and writes the whole `<script>` as a single line, ciphertext first, engine after.
  This hides the engine text and structure; the *security* is still the encryption. Anything the browser can run, a determined person can read.
* **Test-only twin.** `dist/test/*.testable.html` is the same build with the global `FS` left unmangled so the browser tests can compare
  filesystems. **Never ship it.** `dist/nebulink_v1.8.9_vaulted.html` is the one to hand out.
* **Sealed easter egg.** The `rm -rf /*` image is encrypted (key = the wipe command, `gates.json` -> `easter.key`) and carried inside the login vault.
  It is decrypted during the kernel-panic sequence and shown on the next login. Remove the `easter` key to leave it plaintext.
* **Timing.** Login and boot waits are jittered (`sleepJ`): mostly short, a long tail, the odd network hiccup; failed password is slower.
  The panic is a ~5 s sequence (rm errors, accelerating I/O errors, a hang, KERNEL PANIC, sync, disconnect) and the terminal is frozen meanwhile.
  After the crash the next login runs a short fsck before the image.
