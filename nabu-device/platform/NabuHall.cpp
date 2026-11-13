// SPDX-License-Identifier: BSD-2-Clause-Patent
// Default-off, read-only Hall sampler. System HES event delivery is a separate
// 21H16 integration gate. The chosen property alone supplies hardware state.
#include "NabuHall.h"

#ifndef XNU_NABU_HALL
#define XNU_NABU_HALL 0
#endif
#if XNU_NABU_HALL != 0 && XNU_NABU_HALL != 1
#error XNU_NABU_HALL_must_be_zero_or_one
#endif

#if XNU_NABU_HALL
#include "NabuHallResources.h"
#include <IOKit/IOLib.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IORegistryEntry.h>
#include <libkern/c++/OSData.h>
#include <kern/clock.h>
#include <kern/thread.h>
#include <mach/mach_time.h>
#include <pexpert/pexpert.h>
#include <string.h>

extern "C" kern_return_t thread_terminate(thread_t);

namespace {
uint32_t started = 0;
uint32_t hesStatus = static_cast<uint32_t>(nabu_hall::CoverStatus::Unqualified);

uint64_t nowMs()
{
    uint64_t nanoseconds = 0;
    absolutetime_to_nanoseconds(mach_absolute_time(), &nanoseconds);
    return nanoseconds / 1000000;
}

bool boundFdt(IORegistryEntry *chosen)
{
    const OSData *digest = OSDynamicCast(OSData, chosen->getProperty(nabu_hall::FdtProperty));
    return digest && digest->getLength() == sizeof(nabu_hall::SourceFdtSha256) &&
        digest->getBytesNoCopy() &&
        memcmp(digest->getBytesNoCopy(), nabu_hall::SourceFdtSha256,
               sizeof(nabu_hall::SourceFdtSha256)) == 0;
}

void runHall()
{
    IORegistryEntry *chosen = IORegistryEntry::fromPath("/chosen", gIODTPlane);
    if (!chosen || !boundFdt(chosen)) {
        IOLog("NABU HALL gate=source-fdt-binding\n");
        if (chosen) { chosen->release(); }
        __atomic_store_n(&started, 0, __ATOMIC_RELEASE);
        return;
    }

    IODeviceMemory *memory = IODeviceMemory::withRange(nabu_hall::GpioPhysical, nabu_hall::MapBytes);
    IOMemoryMap *mapping = memory ? memory->map(kIOMapAnywhere | kIOMapInhibitCache) : nullptr;
    if (memory) { memory->release(); }
    if (!mapping || !mapping->getVirtualAddress() || mapping->getLength() != nabu_hall::MapBytes) {
        IOLog("NABU HALL gate=gpio-map\n");
        if (mapping) { mapping->release(); }
        chosen->release();
        __atomic_store_n(&started, 0, __ATOMIC_RELEASE);
        return;
    }

    const volatile uint32_t *registers =
        reinterpret_cast<const volatile uint32_t *>(mapping->getVirtualAddress());
    IOLog("NABU HALL sampler pa=%#llx gpio=9 active-low=1 debounce-ms=%u poll-ms=%u\n",
          (unsigned long long)nabu_hall::GpioPhysical, nabu_hall::DebounceMs, nabu_hall::PollMs);
    IOLog("NABU HALL HES gate=21h16-native-interface missing=%#x\n", nabu_hall::NativeCoverMissing);
    nabu_hall::State state;
    uint64_t sequence = 0;
    bool publicationFailed = false;
    for (;;) {
        const uint32_t config = registers[0];
        if (!nabu_hall::inputConfigUsable(config)) {
            IOLog("NABU HALL gate=gpio-input-config config=%#x\n", config);
            break;
        }
        const uint32_t raw = registers[1];
        if (state.sample(raw, nowMs())) {
            const bool published = chosen->setProperty(nabu_hall::StateProperty, state.closed());
            state.acknowledge(published);
            if (published) {
                IOLog("NABU HALL state=%s raw=%#x sequence=%llu published=1\n",
                      state.closed() ? "closed" : "open", raw, (unsigned long long)++sequence);
            } else if (!publicationFailed) {
                IOLog("NABU HALL gate=state-publication retry=pending\n");
            }
            publicationFailed = !published;
        }
        IOSleep(nabu_hall::PollMs);
    }
    // Once the input configuration becomes invalid, a consumer must see an
    // unavailable state instead of the last valid sample.
    chosen->removeProperty(nabu_hall::StateProperty);
    mapping->release();
    chosen->release();
    __atomic_store_n(&started, 0, __ATOMIC_RELEASE);
}

void hallThread(void *, wait_result_t)
{
    runHall();
    thread_terminate(current_thread());
}
} // namespace
#endif

extern "C" bool nabu_hall_start(void)
{
#if XNU_NABU_HALL
    uint32_t enabled = 0;
    if (!PE_parse_boot_argn("nabu-hall", &enabled, sizeof(enabled)) || enabled != 1) { return false; }
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&started, &expected, 1, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        return true;
    }
    thread_t thread;
    const kern_return_t result = kernel_thread_start(hallThread, nullptr, &thread);
    if (result != KERN_SUCCESS) {
        __atomic_store_n(&started, 0, __ATOMIC_RELEASE);
        IOLog("NABU HALL gate=worker-start status=%d\n", result);
        return false;
    }
    thread_deallocate(thread);
    return true;
#else
    return false;
#endif
}

extern "C" uint32_t nabu_hall_hes_missing(void)
{
#if XNU_NABU_HALL
    return nabu_hall::NativeCoverMissing;
#else
    return nabu_hall::NativeCoverMissing | nabu_hall::CompiledOut;
#endif
}

extern "C" nabu_hall::CoverStatus nabu_hall_hes_subscribe(
    const nabu_hall::CoverOps *ops, const uint8_t sourceFdtSha256[32])
{
#if XNU_NABU_HALL
    using nabu_hall::CoverStatus;
    CoverStatus status = CoverStatus::Unqualified;
    if (!ops || !ops->publish || !ops->withdraw || !sourceFdtSha256) {
        status = CoverStatus::InvalidOps;
    } else if (memcmp(sourceFdtSha256, nabu_hall::SourceFdtSha256, 32)) {
        status = CoverStatus::SourceMismatch;
    }
    __atomic_store_n(&hesStatus, static_cast<uint32_t>(status), __ATOMIC_RELEASE);
    return status;
#else
    (void)ops;
    (void)sourceFdtSha256;
    return nabu_hall::CoverStatus::Disabled;
#endif
}

extern "C" nabu_hall::CoverStatus nabu_hall_hes_unsubscribe(void)
{
    // Preserve the current native qualification failure for inspection.
#if XNU_NABU_HALL
    return nabu_hall::CoverStatus::Inactive;
#else
    return nabu_hall::CoverStatus::Disabled;
#endif
}

extern "C" nabu_hall::CoverStatus nabu_hall_hes_status(void)
{
#if XNU_NABU_HALL
    return static_cast<nabu_hall::CoverStatus>(__atomic_load_n(&hesStatus, __ATOMIC_ACQUIRE));
#else
    return nabu_hall::CoverStatus::Disabled;
#endif
}
