#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

KAT="$SRC/mayhem/out/kat"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/mayhem-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
export TMPDIR="$WORK"

PASSED=0
FAILED=0
# check <name> <expected> <actual>: one behavioural known-answer comparison
check() {
  if [ "$2" == "$3" ]; then
    PASSED=$((PASSED + 1))
    echo "PASS $1"
  else
    FAILED=$((FAILED + 1))
    echo "FAIL $1" >&2
    diff <(printf '%s\n' "$2") <(printf '%s\n' "$3") >&2 || true
  fi
}

for b in kat_nvram kat_ead bcm4908img osafeloader; do
  if [ ! -x "$KAT/$b" ]; then
    echo "missing $KAT/$b: mayhem/build.sh did not build it" >&2
    emit_ctrf "mayhem-kat" 0 1 0
    exit 1
  fi
done

# --- package/utils/nvram: build, commit (CRC8 + length), reparse; reject bad magic; ignore an unterminated tail
nvram_out="$("$KAT/kat_nvram" 2>&1)"
check "nvram: committed image header and reparsed variables" \
'hdr: magic=48534c46 len=132 ver=1 crc=b1
boardtype=0x04cf
boardnum=42
gone=(null)
sdram_init=0x0000
sdram_config=0x0000
sdram_refresh=0x0000
sdram_ncdl=0x00000000' "$(printf '%s\n' "$nvram_out" | sed -n 1,8p)"
check "nvram: oversized length with unterminated trailing variable" \
'boardtype=0x0472
boardnum=42
et0macaddr=00:11:22:33:44:55
tail=(null)' "$(printf '%s\n' "$nvram_out" | sed -n 9,12p)"
check "nvram: image without magic is rejected" 'nomagic: rejected' "$(printf '%s\n' "$nvram_out" | sed -n 13p)"

# --- package/network/services/ead: MD5 crypt, AES-128 + SHA-1 message protection, tamper rejection
ead_out="$("$KAT/kat_ead" 2>&1)"
check "ead: md5 crypt of password/\$1\$salt\$" \
'md5crypt: $1$salt$qJH7.N4xYta3aEG/dfqo/0' "$(printf '%s\n' "$ead_out" | sed -n 1p)"
check "ead: encrypted command message bytes" \
'enclen: 64
dc5bdd04261e1b2c244e52881a1303b2ad1da9491e52f179c7d6213b5a2e72b4815c2cbc7c3585ccc52ea3107a7e9208c6a13b37878f5b826f4f8162a1c8d879' \
  "$(printf '%s\n' "$ead_out" | sed -n 2,3p)"
check "ead: decrypt recovers the command" \
'declen: 11
dectext: echo hi' "$(printf '%s\n' "$ead_out" | sed -n 4,5p)"
check "ead: truncated message fails authentication" 'badlen: 0' "$(printf '%s\n' "$ead_out" | sed -n 6p)"

# --- package/utils/bcm4908img: layout and checksum of a known image
check "bcm4908img: info on the reference image" \
'bootfs offset:	0x0
padding offset:	0x20000
rootfs offset:	0x40000
Checksum:	0x0862f8f4' "$("$KAT/bcm4908img" info -i mayhem/kat/bcm4908.img 2>&1)"

# --- package/utils/osafeloader: partition table, image MD5, partition extraction
check "osafeloader: info on the reference image" \
'Image size: 16384
       MD5: 05f99b19fea859046df7cbd789e6fb83
 Partition: os-image (0x400 - 0x4f0)
 Partition: file-system (0x800 - 0xb20)' "$("$KAT/osafeloader" info mayhem/kat/safeloader.bin 2>&1)"
"$KAT/osafeloader" extract mayhem/kat/safeloader.bin -p file-system -o "$WORK/fs.bin" >/dev/null 2>&1 || true
check "osafeloader: extracted partition size and digest" \
'800 bb7eb12377b111bd108fe913c7df34451755053b7656dcd1fbec300b07d96399' \
  "$( [ -f "$WORK/fs.bin" ] && echo "$(stat -c %s "$WORK/fs.bin") $(sha256sum "$WORK/fs.bin" | cut -d' ' -f1)" || echo missing)"

emit_ctrf "mayhem-kat" "$PASSED" "$FAILED" 0
