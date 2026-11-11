/* SPDX-License-Identifier: MIT */
/* Included after NativeUfs host primitives by the explicit Wi-Fi build. */
#include "NabuWifiVolume.h"
#include "NabuWifiBundle.h"
#include "NabuWifiCompressed.h"
#include "NabuWifiInflate.h"
#include "NabuWifiFirmware.h"
#include <IOKit/IORegistryEntry.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <libkern/c++/OSData.h>
#include <libkern/crypto/sha2.h>

static uint8_t *nabu_wifi_package;
static nabu_wifi::FirmwareBundle nabu_wifi_bundle;
static bool nabu_wifi_load_attempted;

static void nabuWifiDigest(const void *data, size_t bytes, uint8_t digest[32]) {
    SHA256_CTX context;
    SHA256_Init(&context);
    SHA256_Update(&context, data, bytes);
    SHA256_Final(digest, &context);
}
static void *nabuWifiZalloc(size_t bytes) {
    return IOMalloc(bytes);
}
static void nabuWifiZfree(void *address, size_t bytes) {
    IOFree(address, bytes);
}
static uint8_t *nabuWifiUnpack(const nabu_wifi::CompressedFirmware &input) {
    uint8_t *raw = static_cast<uint8_t *>(IOMalloc(input.raw_bytes));
    if (!raw) return nullptr;
    const nabu_wifi::InflateResult result = nabu_wifi::inflateFirmware(
        input, raw, input.raw_bytes, {nabuWifiZalloc, nabuWifiZfree});
    if (!result.valid) {
        IOLog("NABU WIFI input error gate=zlib-stream result=%d end=%d in=%lu out=%lu\n",
              result.status, result.ended, static_cast<unsigned long>(result.input_bytes),
              static_cast<unsigned long>(result.output_bytes));
        IOFree(raw, input.raw_bytes);
        return nullptr;
    }
    return raw;
}
static int nabuWifiRead(void *, uint64_t lba, uint32_t blocks, uint8_t *data) {
    if (!gHost.ready || gHost.poisoned || !gHost.lock || !blocks || !data ||
        lba >= nabu_wifi_lun_blocks || blocks > nabu_wifi_lun_blocks - lba ||
        blocks > kDataMax / 4096) return 0;
    uint64_t deadline;
    clock_interval_to_deadline(100, kMillisecondScale, &deadline);
    for (unsigned attempt = 0; attempt < 1000; ++attempt) {
        if (IOLockTryLock(gHost.lock)) {
            uint8_t cdb[10] = {0x28};
            cdb[2] = uint8_t(lba >> 24); cdb[3] = uint8_t(lba >> 16);
            cdb[4] = uint8_t(lba >> 8); cdb[5] = uint8_t(lba);
            cdb[7] = uint8_t(blocks >> 8); cdb[8] = uint8_t(blocks);
            uint32_t scsi = 0;
            const IOReturn result = hostScsiDir(0, cdb, 10, 2, blocks * 4096, 1000000, &scsi);
            if (result == kIOReturnSuccess) memcpy(data, gHost.virt + kDataOffset, blocks * 4096);
            IOLockUnlock(gHost.lock);
            if (result != kIOReturnSuccess) {
                IOLog("NABU WIFI read error lba=%llu blocks=%u result=%08x scsi=%u\n", lba, blocks, result, scsi);
            }
            return result == kIOReturnSuccess;
        }
        if (mach_absolute_time() >= deadline) break;
        thread_yield_internal(1);
    }
    IOLog("NABU WIFI read error gate=host-lock-timeout\n");
    return 0;
}
extern "C" int nabu_wifi_firmware_load() {
    if (nabu_wifi_load_attempted) return 1;
    nabu_wifi_load_attempted = true;
    uint8_t expected[32];
    IORegistryEntry *chosen = IORegistryEntry::fromPath("/chosen", gIODTPlane);
    OSData *identity = chosen ? OSDynamicCast(OSData, chosen->getProperty("nabu-wifi-package-sha256")) : nullptr;
    const bool bound = identity && identity->getLength() == sizeof(expected);
    if (bound) memcpy(expected, identity->getBytesNoCopy(), sizeof(expected));
    if (chosen) chosen->release();
    if (!bound) { IOLog("NABU WIFI input error gate=external-package-digest\n"); return 2; }
    nabu_wifi_volume *volume = static_cast<nabu_wifi_volume *>(IOMalloc(sizeof(nabu_wifi_volume)));
    if (!volume) { IOLog("NABU WIFI input error gate=volume-allocation\n"); return 3; }
    if (!nwv_open(volume, nabuWifiRead, nullptr, nabu_wifi_lun_blocks)) {
        IOLog("NABU WIFI input error gate=%s reads=%u\n", volume->failure, volume->media.reads);
        IOFree(volume, sizeof(*volume));
        return 4;
    }
    size_t bytes = volume->file_bytes;
    uint8_t *package = static_cast<uint8_t *>(IOMalloc(bytes));
    const bool copied = package && nwv_copy_file(volume, package, bytes);
    IOLog("NABU WIFI input media esp_lba=%llu file_cluster=%u bytes=%lu reads=%u copied=%u gate=%s\n",
          volume->media.esp_first, volume->media.file_cluster, bytes, volume->media.reads, copied, volume->failure);
    IOFree(volume, sizeof(*volume));
    if (copied && !memcmp(package, "NWIFIZ01", 8)) {
        nabu_wifi::CompressedFirmware compressed{};
        uint8_t *raw = nullptr;
        if (nabu_wifi::CompressedFirmware::inspect(package, bytes, expected, nabuWifiDigest, &compressed)) {
            IOLog("NABU WIFI input container verified bytes=%lu compression=zlib raw_bytes=%lu\n",
                  bytes, compressed.raw_bytes);
            raw = nabuWifiUnpack(compressed);
        }
        IOFree(package, bytes);
        package = raw;
        bytes = compressed.raw_bytes;
        memcpy(expected, compressed.raw_digest, sizeof(expected));
    }
    if (!copied || !package || !nabu_wifi_bundle.open(package, bytes, expected, nabuWifiDigest)) {
        if (package) IOFree(package, bytes);
        IOLog("NABU WIFI input error gate=package-integrity\n");
        return 5;
    }
    nabu_wifi_package = package;
    char hex[65];
    static const char digits[] = "0123456789abcdef";
    for (unsigned i = 0; i < 32; ++i) { hex[2 * i] = digits[expected[i] >> 4]; hex[2 * i + 1] = digits[expected[i] & 15]; }
    hex[64] = 0;
    IOLog("NABU WIFI input verified bytes=%lu files=%u sha256=%s\n", bytes, nabu_wifi_bundle.fileCount(), hex);
    const uint8_t *bundle_id = nabu_wifi_bundle.bundleId();
    for (unsigned i = 0; i < 32; ++i) { hex[2 * i] = digits[bundle_id[i] >> 4]; hex[2 * i + 1] = digits[bundle_id[i] & 15]; }
    IOLog("NABU WIFI input bundle_id=%s provider=immutable-memory\n", hex);
    return 0;
}
extern "C" bool nabu_wifi_firmware_file(const char *path, const uint8_t **data, size_t *bytes) {
    return nabu_wifi_package && nabu_wifi_bundle.getFile(path, data, bytes);
}
