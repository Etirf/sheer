# sheer

```
$ shrun "git reset --hard HEAD~3"

  git reset --hard HEAD~3
  ------------------------

  Throws away the last 3 commits. Permanently.

  risk     ▲ HIGH
  warning  This rewrites history. Unpushed commits are gone forever.
  safer    git stash if you might want them back.

  run it? [y/N]
```

Stop pasting and praying.

---

Offline. ~1ms. C binary, no runtime deps, works on anything with a libc.

`man rm` tells you what `rm` does. sheer tells you what `rm -rf /var/log/nginx` does - right now, to that path, with those flags.

- **`sheer "cmd"`** - explains the command, shows risk. Nothing is executed
- **`shrun "cmd"`** - same thing, then asks `run it? [y/N]` and executes if you confirm

---

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/etirf/sheer/main/install.sh | sh
```

Downloads the pre-built binary for your arch, adds `shrun` to your shell. Open a new terminal and you're all set.

The installer automatically verifies the binary's SHA256 checksum against the release. To verify manually:

```sh
curl -fsSL https://github.com/etirf/sheer/releases/latest/download/checksums.txt
sha256sum /usr/local/bin/sheer
```

From source (needs `cc` and `make`, nothing else):

```sh
curl -fsSL https://raw.githubusercontent.com/etirf/sheer/main/install.sh | sh -s -- --from-source
# or: git clone https://github.com/etirf/sheer && cd sheer && make && sudo make install
```

---

## Pipelines

sheer breaks down each stage separately:

```
$ sheer "find /var/log -name '*.log' | xargs rm"

  [1/2]  find /var/log -name '*.log'
         Searches /var/log for files matching '*.log'.
         risk  ▲ MODERATE
           │
  [2/2]  xargs rm
         Runs rm once per match.
         risk  ▲ HIGH
         warning  xargs amplifies rm - one wrong glob, everything's gone.
         safer    xargs echo rm first to preview what would run.

  pipeline  ▲ HIGH
```

Works with `|`, `&&`, `||`, and `;`.

---

## LLM fallback

60+ commands are covered offline - `rm`, `find`, `git`, `docker`, `ssh`, `tar`, `systemctl`, `iptables`, `dd`, and everything else that can actually hurt you. For the rest, or to generate commands from plain English:

```sh
sheer config llm=ollama
sheer config model=llama3
```

```sh
sheer "kubectl drain node-1 --ignore-daemonsets"

sheer gen "delete log files older than 7 days"
sheer gen --context "restart whatever I was running before"
```

Works with Ollama, LM Studio, llama.cpp, vLLM, or any OpenAI-compatible endpoint.

---

## Contributing

Add a command: write `analyze_foo()` in `src/cmd.c`, drop it in `cmd_table`. Table auto-sorts at runtime.

```sh
make test   # integration tests
make bench  # fails if avg > 20ms
make debug  # ASan + UBSan build
```

---

MIT
