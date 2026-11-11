#!/usr/bin/env bash
#
# mayhem/build.sh — OpenWrt's `source` tree is a build system whose real code lives in external tarballs;
# what is in the tree and buildable stand-alone is a handful of small C utilities. This builds the ones
# we fuzz, each from the in-tree sources exactly as the package Makefiles do (no upstream file is edited):
#   fuzz_nvram          package/utils/nvram                  (libFuzzer, in-process)
#   fuzz_ead_client     package/network/services/ead         (libFuzzer, in-process, client reply handlers)
#   bcm4908img          package/utils/bcm4908img             (raw file-input CLI)
#   osafeloader         package/utils/osafeloader            (raw file-input CLI)
# plus the unsanitized KAT probes that mayhem/test.sh runs.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

SRC="${SRC:-/mayhem}"
cd "$SRC"

NVRAM=package/utils/nvram/src
EAD=package/network/services/ead/src
BCM=package/utils/bcm4908img/src
OSL=package/utils/osafeloader/src
OUT="$SRC/mayhem/out"
rm -rf "$OUT"
mkdir -p "$OUT/san" "$OUT/kat" "$OUT/cfg"

# Instrumented compile: ASan+UBSan (halting) from $SANITIZER_FLAGS, DWARF 3, and SanCov on the fuzzed code
# unconditionally (also with SANITIZER_FLAGS empty).
san_cc() {
	$CC $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1 -w "$@"
}
# Normal-flags compile for the test oracle: no sanitizers, no -gdwarf-3.
kat_cc() {
	$CC -O2 -w $COVERAGE_FLAGS "$@"
}

# --- LeakSanitizer off (SPEC 6.2 item 15) -------------------------------------------------------------
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$OUT/san/lsan_off.o"
# Weak no-op SanCov callbacks for the binaries that don't link libFuzzer (-standalone, raw CLIs): with an empty
# $SANITIZER_FLAGS nothing else defines them.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/sancov_stub.c -o "$OUT/san/sancov_stub.o"

# --- tinysrp (ead's SRP library): upstream's autoconf 2.13 `configure` can't probe clang, so use the
#     values it would find on Linux/x86-64 and the library's own source list (tinysrp/Makefile.am).
cat > "$OUT/cfg/config.h" <<'CFG'
#define STDC_HEADERS 1
#define TIME_WITH_SYS_TIME 1
#define SIZEOF_INT 4
#define SIZEOF_LONG 8
#define SIZEOF_LONG_LONG 8
#define SIZEOF_SHORT 2
#define HAVE_MEMCPY 1
#define HAVE_SIGACTION 1
#define HAVE_STRCHR 1
#define HAVE_SYS_IOCTL_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_TERMIOS_H 1
#define HAVE_UNISTD_H 1
#define POSIX_TERMIOS 1
#define POSIX_SIGTYPE 1
#define RETSIGTYPE void
#define PACKAGE "tinysrp"
#define VERSION "1.0"
CFG
TINYSRP_SRCS="tinysrp t_client t_getconf t_conv t_getpass t_sha t_math t_misc t_pw t_read t_server t_truerand \
 bn_add bn_ctx bn_div bn_exp bn_mul bn_word bn_asm bn_lib bn_shift bn_sqr"
TINYSRP_CFLAGS="-DHAVE_CONFIG_H -I$OUT/cfg -I$EAD/tinysrp -I$EAD"
for f in $TINYSRP_SRCS; do
	san_cc $TINYSRP_CFLAGS -c "$EAD/tinysrp/$f.c" -o "$OUT/san/tsrp_$f.o"
done
TINYSRP_OBJS=$(for f in $TINYSRP_SRCS; do printf '%s ' "$OUT/san/tsrp_$f.o"; done)

# --- nvram -----------------------------------------------------------------------------------------------
# nvram.c computes `SDRAM_REFRESH << 16` (0x8040, an int) on every commit of an image without sdram_* variables:
# a constant, benign signed-shift overflow that would stop every run, so only shift-base is relaxed, on this file.
san_cc -fno-sanitize=shift-base -I"$NVRAM" -c "$NVRAM/nvram.c" -o "$OUT/san/nvram_nvram.o"
san_cc -I"$NVRAM" -c "$NVRAM/crc.c" -o "$OUT/san/nvram_crc.o"
san_cc -I"$NVRAM" -c mayhem/fuzz_nvram/fuzz_nvram.c -o "$OUT/san/fuzz_nvram.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
	"$OUT/san/fuzz_nvram.o" "$OUT/san/nvram_nvram.o" "$OUT/san/nvram_crc.o" "$OUT/san/lsan_off.o" \
	-o /mayhem/fuzz_nvram
$CC $SANITIZER_FLAGS $DEBUG_FLAGS "$STANDALONE_FUZZ_MAIN" \
	"$OUT/san/fuzz_nvram.o" "$OUT/san/nvram_nvram.o" "$OUT/san/nvram_crc.o" "$OUT/san/lsan_off.o" "$OUT/san/sancov_stub.o" \
	-o /mayhem/fuzz_nvram-standalone

# --- ead client ---------------------------------------------------------------------------------------------
# ead-crypt.c calls htonl()/ntohl() without including <arpa/inet.h> (an implicit declaration, rejected by clang).
# It includes aes.c, whose key schedule does `rcon[i] << 24` on an int (0x80 << 24) for every key: a constant,
# benign shift overflow, so only shift-base is relaxed on this file.
san_cc -fno-sanitize=shift-base -include arpa/inet.h -I"$EAD" -c "$EAD/ead-crypt.c" -o "$OUT/san/ead_crypt.o"
# the harness includes ead-client.c itself to reach its static handlers; its main() is renamed
san_cc $TINYSRP_CFLAGS -Dmain=ead_client_main -I"$EAD" -c mayhem/fuzz_ead_client/fuzz_ead_client.c -o "$OUT/san/fuzz_ead_client.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
	"$OUT/san/fuzz_ead_client.o" "$OUT/san/ead_crypt.o" $TINYSRP_OBJS "$OUT/san/lsan_off.o" \
	-o /mayhem/fuzz_ead_client
$CC $SANITIZER_FLAGS $DEBUG_FLAGS "$STANDALONE_FUZZ_MAIN" \
	"$OUT/san/fuzz_ead_client.o" "$OUT/san/ead_crypt.o" $TINYSRP_OBJS "$OUT/san/lsan_off.o" "$OUT/san/sancov_stub.o" \
	-o /mayhem/fuzz_ead_client-standalone

# --- raw file-input CLIs (Mayhem drives them with @@) ---------------------------------------------------------
san_cc -c "$BCM/bcm4908img.c" -o "$OUT/san/bcm4908img.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/san/bcm4908img.o" "$OUT/san/lsan_off.o" "$OUT/san/sancov_stub.o" -o /mayhem/bcm4908img
san_cc -c "$OSL/osafeloader.c" -o "$OUT/san/osafeloader.o"
san_cc -c "$OSL/md5.c" -o "$OUT/san/osafeloader_md5.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/san/osafeloader.o" "$OUT/san/osafeloader_md5.o" "$OUT/san/lsan_off.o" "$OUT/san/sancov_stub.o" -o /mayhem/osafeloader

# --- test oracle: the same sources with their normal flags, no sanitizers ------------------------------------
kat_cc -I"$NVRAM" mayhem/kat/kat_nvram.c "$NVRAM/nvram.c" "$NVRAM/crc.c" -o "$OUT/kat/kat_nvram"
kat_cc -include arpa/inet.h -I"$EAD" mayhem/kat/kat_ead.c "$EAD/ead-crypt.c" -o "$OUT/kat/kat_ead"
kat_cc "$BCM/bcm4908img.c" -o "$OUT/kat/bcm4908img"
kat_cc "$OSL/osafeloader.c" "$OSL/md5.c" -o "$OUT/kat/osafeloader"
