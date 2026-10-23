#!/usr/bin/env bash
# Runs on the GitHub Actions macOS runner; no rented-Mac fallback.
set -euo pipefail
KIT=$(cd -- "$(dirname -- "$0")" && pwd)
MODE=${1:---preflight}
case "$MODE" in
  --preflight)
    test "$(uname -s)" = Darwin || { echo 'Run on the newly authorized Mac' >&2; exit 1; }
    mkdir -p "$KIT/output"
    date '+%Y-%m-%dT%H:%M:%S%z' > "$KIT/output/preflight.log"
    xcodebuild -version >> "$KIT/output/preflight.log"
    xcrun --sdk iphoneos --show-sdk-path >> "$KIT/output/preflight.log"
    xcrun clang --version >> "$KIT/output/preflight.log"
    xcrun ld -v >> "$KIT/output/preflight.log" 2>&1
    xcrun clang -print-resource-dir >> "$KIT/output/preflight.log"
    python3 "$KIT/check_batch_inputs.py" >> "$KIT/output/preflight.log"
    ;;
  --build-captured|--build-prelinked|--build-integrated-ufs)
    test "$(uname -s)" = Darwin || { echo 'Run on the newly authorized Mac' >&2; exit 1; }
    ROOT=${2:?Usage: --build-captured NEW_EMPTY_PRIVATE_ROOT}
    bash "$KIT/run_mac_batch.sh" --preflight
    python3 "$KIT/prepare_mac_workspace.py" "$ROOT"
    CRYPTO_MODE=source
    if [ "$MODE" != --build-captured ]; then CRYPTO_MODE=prelinked; fi
    if [ "$MODE" = --build-integrated-ufs ]; then
      python3 "$KIT/compile_captured_mac.py" "$ROOT" --crypto-bootstrap "$CRYPTO_MODE" --native-ufs
    else
      python3 "$KIT/compile_captured_mac.py" "$ROOT" --crypto-bootstrap "$CRYPTO_MODE"
    fi
    if [ "$MODE" = --build-integrated-ufs ]; then
      UFS_SOURCE=${3:?Supply the prepared pinned NativeUfs source}
      python3 "$KIT/compile_native_ufs.py" "$ROOT" --source "$UFS_SOURCE"
      python3 "$KIT/native_ufs_bindings.py" --object "$ROOT/mac-batch-output/native-ufs/NativeUfs.o" --output-dir "$ROOT/mac-batch-output/native-ufs"
    fi
    python3 "$KIT/link_captured_mac.py" "$ROOT"
    ;;
  --archive-corecrypto)
    SOURCE=${2:?Usage: --archive-corecrypto EXACT_PRIVATE_GIT_SOURCE}
    REVISION=11fba65b12d8830630e248dfa8344caf8b065f26
    test "$(git -C "$SOURCE" rev-parse HEAD)" = "$REVISION" || { echo 'Wrong crypto source revision' >&2; exit 1; }
    test -z "$(git -C "$SOURCE" status --porcelain)" || { echo 'Preserve and inspect changed crypto source' >&2; exit 1; }
    mkdir -p "$KIT/output"
    git -C "$SOURCE" archive --format=tar.gz --prefix=corecrypto-2023/ HEAD > "$KIT/output/corecrypto-2023-$REVISION.tar.gz"
    git -C "$SOURCE" rev-parse HEAD > "$KIT/output/corecrypto-source-revision.txt"
    tar -tzf "$KIT/output/corecrypto-2023-$REVISION.tar.gz" > "$KIT/output/corecrypto-archive-files.txt"
    ;;
  --build-clean)
    test "$(uname -s)" = Darwin || { echo 'Run on the newly authorized Mac' >&2; exit 1; }
    CLEAN=${2:?Usage: --build-clean NEW_EMPTY_ROOT EXACT_FULL_PRIVATE_RESOURCE_ROOT}
    FULL=${3:?Supply exact complete private source/resource root}
    bash "$KIT/run_mac_batch.sh" --preflight
    python3 "$KIT/check_batch_inputs.py" --full-root "$FULL"
    python3 "$KIT/prepare_clean_mac.py" "$CLEAN" "$FULL"
    cd "$CLEAN"
    export XNU_SOURCE_CORECRYPTO14=1 XNU_SOURCE_PTHREAD=1 XNU_ARM_DT_PLATFORM=1 XNU_ARMCPU=1
    export XNU_NATIVE_ARCH_TIMER=1 XNU_DT_PANIC_REGION=1 XNU_SOURCE_MOCKFS=1
    export XNU_TRUST_CACHE_RUNTIME=0 XNU_NATIVE_CS_HASH_CACHE=0 XNU_NATIVE_PAN=1
    export XNU_EXTRA_CFLAGS='-DXNU_NABU_MOCKFS_EL0=1 -Wno-unknown-warning-option -Wno-error'
    JOBS=2 bash scripts/build-xnu-offline.sh > mac-clean-build.log 2>&1
    ;;
  --apfs-fixture)
    test "$(uname -s)" = Darwin || { echo 'APFS fixture creation requires the authorized macOS runner' >&2; exit 1; }
    OUTPUT=${2:?Usage: --apfs-fixture NEW_OUTPUT_DIR}
    python3 "$KIT/make_apfs_fixture.py" --output-dir "$OUTPUT"
    ;;
  *) echo 'Supported: --preflight, --build-captured NEW_ROOT, --archive-corecrypto EXACT_SOURCE, --build-clean, --apfs-fixture NEW_OUTPUT_DIR' >&2; exit 2 ;;
esac
