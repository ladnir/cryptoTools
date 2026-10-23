#!/usr/bin/env bash
set -euo pipefail
off=${1:?AES-NI frontend_cryptoTools executable}
on=${2:?VAES frontend_cryptoTools executable}
out=${3:?results directory}
cpu=${4:-15}
mkdir -p "$out"
exec 8>/tmp/prindal-addition-encoder-benchmark.lock
exec 9>/tmp/bare-spin-benchmark.lock
exec 7>/tmp/hypercat-benchmark.lock
flock -n 8
flock -n 9
flock -n 7
for repeat in 1 2 3; do
    taskset -c "$cpu" "$off" -aesBench > "$out/aes-off-$repeat.csv"
    taskset -c "$cpu" "$on" -aesBench > "$out/aes-on-$repeat.csv"
done
