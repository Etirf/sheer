#!/usr/bin/env bash
# if it's slower than man, we've failed at life...
set -euo pipefail

BIN="${BIN:-./sheer}"
ITERATIONS="${ITERATIONS:-200}"
MAX_MS="${MAX_MS:-20}"

CMDS=(
    "rm -rf /tmp/*"
    "git push --force origin main"
    "dd if=/dev/urandom of=/dev/sda"
    "chmod -R 777 /var/www"
    "docker run --privileged --rm ubuntu bash"
    "find /var/log -name '*.log' -mtime +7 -delete"
    "rsync -a --delete /src /dst"
    "iptables -F INPUT"
    "sudo rm -rf /etc"
    "tar -czf backup.tar.gz ./app"
)

echo ""
echo "  sheer offline benchmark - ${ITERATIONS} iterations per command"
echo ""

total_ms=0
n_cmds=0

for cmd in "${CMDS[@]}"; do
    cmd_total=0
    for i in $(seq 1 "$ITERATIONS"); do
        t_start=$(date +%s%N)
        "$BIN" "$cmd" > /dev/null 2>&1
        t_end=$(date +%s%N)
        cmd_total=$(( cmd_total + (t_end - t_start) / 1000000 ))
    done
    avg=$(( cmd_total / ITERATIONS ))
    total_ms=$(( total_ms + avg ))
    n_cmds=$(( n_cmds + 1 ))
    printf "  %-52s %3dms avg\n" "\"$cmd\"" "$avg"
done

overall=$(( total_ms / n_cmds ))
echo ""
printf "  overall average: %dms\n" "$overall"

if [ "$overall" -gt "$MAX_MS" ]; then
    echo ""
    echo "  FAIL: ${overall}ms > ${MAX_MS}ms - something got slow, fix it"
    echo "  (slow machine? re-run with MAX_MS=<higher>)"
    exit 1
fi

echo "  PASS: ${overall}ms"
echo ""
