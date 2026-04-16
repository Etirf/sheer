#!/usr/bin/env bash
# if this breaks, something is wrong. don't ship it.
set -euo pipefail

BIN="${BIN:-./sheer}"
PASS=0
FAIL=0
ERRS=()

ok()   { PASS=$((PASS+1)); }
fail() { FAIL=$((FAIL+1)); ERRS+=("$*"); }

assert_contains() {
    local desc="$1" cmd="$2" want="$3"
    local got
    got=$("$BIN" "$cmd" 2>&1)
    if echo "$got" | grep -qF "$want"; then
        ok
    else
        fail "FAIL [$desc]: expected '$want' not found"
        fail "     output: $(echo "$got" | head -5)"
    fi
}

assert_risk() { assert_contains "$1" "$2" "$3"; }

# risk levels
assert_risk "rm -rf / is CRITICAL"               "rm -rf /"                       "CRITICAL"
assert_risk "rm -rf /tmp/* is HIGH"              "rm -rf /tmp/*"                  "HIGH"
assert_risk "rm single file is LOW"              "rm notes.txt"                   "LOW"
assert_risk "git push --force is CRITICAL"       "git push --force origin main"   "CRITICAL"
assert_risk "git push normal is SAFE"            "git push origin main"           "SAFE"
assert_risk "git push --force-with-lease MODERATE" "git push --force-with-lease"  "MODERATE"
assert_risk "git reset --hard is HIGH"           "git reset --hard HEAD~3"        "HIGH"
assert_risk "git reset --soft is LOW"            "git reset --soft HEAD~1"        "LOW"
assert_risk "git clean -f is HIGH"               "git clean -f"                   "HIGH"
assert_risk "git clean -n is SAFE"               "git clean -n"                   "SAFE"
assert_risk "chmod 777 is HIGH"                  "chmod -R 777 /var/www"          "HIGH"
assert_risk "chmod 644 is LOW"                   "chmod 644 file.txt"             "LOW"
assert_risk "dd wipe /dev/sda is CRITICAL"       "dd if=/dev/urandom of=/dev/sda" "CRITICAL"
assert_risk "mkfs.ext4 is CRITICAL"              "mkfs.ext4 /dev/sdb1"            "CRITICAL"
assert_risk "iptables -F is CRITICAL"            "iptables -F"                    "CRITICAL"
assert_risk "find -delete is HIGH"               "find /var/log -name '*.log' -delete" "HIGH"
assert_risk "find no delete is SAFE"             "find . -name '*.py'"            "SAFE"
assert_risk "rsync --delete is HIGH"             "rsync -a --delete src/ dst/"    "HIGH"
assert_risk "rsync dry-run is SAFE"              "rsync -n src/ dst/"             "SAFE"
assert_risk "tar list is SAFE"                   "tar -tzf backup.tar.gz"         "SAFE"
assert_risk "docker run --privileged is CRITICAL" "docker run --privileged ubuntu" "CRITICAL"
assert_risk "docker rm -f is HIGH"               "docker rm -f mycontainer"       "HIGH"
assert_risk "sudo rm -rf escalates risk"         "sudo rm -rf /etc"               "CRITICAL"

# explanation content
assert_contains "rm explains deletion"           "rm -rf /tmp/*"          "Deletes"
assert_contains "dd explains overwrite"          "dd if=/dev/urandom of=/dev/sda" "Overwrites"
assert_contains "chmod describes mode"           "chmod 644 file.txt"     "owner"
assert_contains "git reset --hard mentions stash" "git reset --hard HEAD~1" "stash"
assert_contains "git push --force has safer alt" "git push --force"       "force-with-lease"
assert_contains "chmod 777 has safer alt"        "chmod 777 /var/www"     "755"
assert_contains "mkfs warns data loss"           "mkfs.ext4 /dev/sdb1"    "destroyed"
assert_contains "find -delete warns irreversible" "find /tmp -name '*.log' -delete" "irreversible"
assert_contains "rsync --delete warns"           "rsync -a --delete src/ dst/" "delete"
assert_contains "source is local rules"          "rm -rf /tmp/*"          "local rules"

# sudo wrapping
assert_contains "sudo prefixes explanation"      "sudo rm -rf /etc"       "As root:"
assert_contains "sudo rm explains deletion"      "sudo rm -rf /etc"       "Deletes"

# path stripping
assert_risk "/usr/bin/rm is recognized"          "/usr/bin/rm -rf /tmp"   "HIGH"
assert_risk "/bin/mkfs.ext4 is recognized"       "/bin/mkfs.ext4 /dev/sda" "CRITICAL"

# unknown command - should not crash and should say something useful
got=$("$BIN" "unknowncmd --foo bar" 2>&1)
if echo "$got" | grep -qi "not recogni"; then ok
else fail "FAIL [unknown command]: expected 'not recognised' message"
fi

# --version
got=$("$BIN" --version 2>&1)
if echo "$got" | grep -q "sheer"; then ok
else fail "FAIL [--version]: expected version string"
fi

# --help exits 0
"$BIN" --help > /dev/null 2>&1 && ok || fail "FAIL [--help]: non-zero exit"

# empty input shouldn't segfault
"$BIN" "" > /dev/null 2>&1; ok

# pipeline - risk should aggregate to HIGH (xargs rm)
got=$("$BIN" "find /tmp -name '*.log' | xargs rm" 2>&1)
if echo "$got" | grep -q "pipeline"; then ok
else fail "FAIL [pipeline]: expected pipeline output"
fi

# ── docker run multi-port/volume (the fix) ───────────────────────────────────

assert_contains "docker run multi-port shows both"    "docker run -p 80:80 -p 443:443 nginx"  "443"
assert_contains "docker run multi-vol shows both"     "docker run -v /data:/data -v /logs:/logs ubuntu" "logs"
assert_contains "docker run multi-port finds image"   "docker run -p 80:80 -p 443:443 nginx"  "nginx"
assert_risk    "docker run host vol is HIGH"          "docker run -v /etc:/etc ubuntu bash"    "HIGH"

# ── file operations ──────────────────────────────────────────────────────────

assert_risk    "mv to /etc is HIGH"                   "mv config.txt /etc/config"              "HIGH"
assert_contains "mv explains move"                    "mv old.txt new.txt"                     "Move"
assert_risk    "cp is SAFE"                           "cp file.txt backup.txt"                 "SAFE"
assert_risk    "cp -r to /usr is HIGH"                "cp -r src/ /usr/local"                  "HIGH"
assert_risk    "chown root is HIGH"                   "chown root:root /var/app"               "HIGH"
assert_risk    "ln -s is SAFE"                        "ln -s /etc/hosts hosts"                 "SAFE"
assert_risk    "ln hard link is SAFE"                 "ln a.txt b.txt"                         "SAFE"

# ── process management ───────────────────────────────────────────────────────

assert_risk    "kill default is MODERATE"             "kill 1234"                              "MODERATE"
assert_risk    "kill -9 is HIGH"                      "kill -9 1234"                           "HIGH"
assert_contains "kill -9 warns unblockable"           "kill -9 1234"                           "SIGKILL"
assert_risk    "pkill -9 is HIGH"                     "pkill -9 nginx"                         "HIGH"
assert_risk    "killall normal is MODERATE"           "killall node"                           "MODERATE"

# ── network ──────────────────────────────────────────────────────────────────

assert_risk    "curl GET is SAFE"                     "curl https://example.com"               "SAFE"
assert_risk    "curl DELETE is HIGH"                  "curl -X DELETE https://api.example.com/resource" "HIGH"
assert_contains "curl detects method"                 "curl -X POST https://example.com"       "POST"
assert_risk    "wget is LOW"                          "wget https://example.com/file.tar.gz"   "LOW"
assert_risk    "ssh normal is SAFE"                   "ssh user@server.com"                    "SAFE"
assert_risk    "ssh agent forward is MODERATE"        "ssh -A user@server.com"                 "MODERATE"
assert_contains "ssh -A warns agent"                  "ssh -A user@server.com"                 "agent"
assert_risk    "nc listen + exec is CRITICAL"         "nc -l -e /bin/sh -p 4444"              "CRITICAL"
assert_risk    "nc listen is MODERATE"                "nc -l -p 8080"                          "MODERATE"
assert_risk    "scp is LOW"                           "scp file.txt user@host:/tmp"            "LOW"
assert_risk    "ping is SAFE"                         "ping 8.8.8.8"                           "SAFE"

# ── system administration ────────────────────────────────────────────────────

assert_risk    "systemctl stop is MODERATE"           "systemctl stop nginx"                   "MODERATE"
assert_risk    "systemctl start is LOW"               "systemctl start nginx"                  "LOW"
assert_risk    "systemctl mask is HIGH"               "systemctl mask sshd"                    "HIGH"
assert_contains "systemctl mask warns"                "systemctl mask sshd"                    "cannot be started"
assert_risk    "mount device is HIGH"                 "mount /dev/sdb1 /mnt"                   "HIGH"
assert_risk    "mount no args is SAFE"                "mount"                                   "SAFE"
assert_risk    "fdisk is CRITICAL"                    "fdisk /dev/sda"                          "CRITICAL"
assert_risk    "parted is CRITICAL"                   "parted /dev/sda"                         "CRITICAL"
assert_risk    "crontab -e is MODERATE"               "crontab -e"                              "MODERATE"
assert_risk    "crontab -r is HIGH"                   "crontab -r"                              "HIGH"
assert_contains "crontab -r warns"                    "crontab -r"                              "Removes ALL"
assert_risk    "useradd is MODERATE"                  "useradd newuser"                         "MODERATE"
assert_risk    "userdel -r is HIGH"                   "userdel -r olduser"                      "HIGH"

# ── script execution ─────────────────────────────────────────────────────────

assert_risk    "bash -c is HIGH"                      "bash -c 'echo hello'"                   "HIGH"
assert_risk    "bash interactive is SAFE"             "bash"                                    "SAFE"
assert_risk    "python -c is HIGH"                    "python -c 'import os; os.system(\"ls\")'" "HIGH"
assert_risk    "eval is CRITICAL"                     "eval \$SOME_VAR"                         "CRITICAL"
assert_contains "eval warns injection"                "eval foo"                                "injection"
assert_risk    "base64 encode is SAFE"                "base64 file.txt"                         "SAFE"
assert_risk    "base64 decode is MODERATE"            "base64 -d payload"                       "MODERATE"

# ── package managers ─────────────────────────────────────────────────────────

assert_risk    "pip install system is MODERATE"       "pip install requests"                    "MODERATE"
assert_risk    "pip install --user is LOW"            "pip install --user requests"             "LOW"
assert_risk    "npm install global is MODERATE"       "npm install -g typescript"               "MODERATE"
assert_risk    "npm install local is LOW"             "npm install"                             "LOW"
assert_contains "apt install explains"                "apt install nginx"                       "nstall"
assert_contains "apt remove explains"                 "apt remove nginx"                        "emov"

# ── git subcommands ──────────────────────────────────────────────────────────

assert_risk    "git checkout is LOW"                  "git checkout main"                       "LOW"
assert_risk    "git clone is SAFE"                    "git clone https://github.com/foo/bar"    "SAFE"
assert_risk    "git merge is LOW"                     "git merge feature"                       "LOW"
assert_risk    "git rebase is HIGH"                   "git rebase main"                         "HIGH"
assert_risk    "git rebase -i is HIGH"                "git rebase -i HEAD~5"                    "HIGH"
assert_risk    "git stash is SAFE"                    "git stash"                               "SAFE"
assert_risk    "git stash drop is MODERATE"           "git stash drop"                          "MODERATE"
assert_risk    "git diff is SAFE"                     "git diff"                                "SAFE"

# ── docker subcommands ───────────────────────────────────────────────────────

assert_risk    "docker exec is LOW"                   "docker exec mycontainer ls"              "LOW"
assert_risk    "docker exec root is HIGH"             "docker exec --user root mycontainer bash" "HIGH"
assert_risk    "docker stop is LOW"                   "docker stop mycontainer"                  "LOW"
assert_risk    "docker ps is SAFE"                    "docker ps"                                "SAFE"
assert_risk    "docker run --network host is HIGH"    "docker run --network host nginx"          "HIGH"

# ── safe/info commands ───────────────────────────────────────────────────────

assert_risk    "ls is SAFE"                           "ls -la"                                   "SAFE"
assert_risk    "cat is SAFE"                          "cat /etc/passwd"                           "SAFE"
assert_risk    "ps is SAFE"                           "ps aux"                                    "SAFE"
assert_risk    "df is SAFE"                           "df -h"                                     "SAFE"
assert_risk    "grep is SAFE"                         "grep -r TODO ."                            "SAFE"
assert_risk    "echo is SAFE"                         "echo hello"                                "SAFE"

# ── ip6tables alias ──────────────────────────────────────────────────────────

assert_risk    "ip6tables -F is CRITICAL"             "ip6tables -F"                              "CRITICAL"

# report
echo ""
printf "  results: %d passed, %d failed\n" "$PASS" "$FAIL"
for e in "${ERRS[@]}"; do printf "  %s\n" "$e"; done
echo ""

[ "$FAIL" -eq 0 ]
