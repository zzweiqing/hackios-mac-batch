/* SPDX-License-Identifier: MIT */
/* Qualcomm PAS/MDT protocol checked against ios-flame
 * 745c4341af86089efb0df851fa8a27fb8face624, phone/wifi/wland.c, and
 * Linux v6.12 mdt_loader.c / qcom_scm.c. This adapter uses nabu resources.
 */
#include "NabuWifiMpss.h"
#include "NabuWifiPas.h"
#include <string.h>

#ifndef NABU_WIFI_MPSS_HOST_TEST
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOLib.h>
#include <kern/clock.h>
#include <kern/task.h>
#include <mach/vm_param.h>

extern "C" uint64_t gPhysBase, gPhysSize;
#endif

namespace NabuWifiMpss {
namespace {
constexpr size_t MaxHeaders = 128;
constexpr size_t MaxMetadataBytes = 1024 * 1024;
constexpr size_t MaxMdtBytes = 64 * 1024 * 1024;
constexpr size_t MaxOwnedBytes = RmtfsSharedBytes + 0x10000;
constexpr uint32_t HashMask = 7u << 24;
constexpr uint32_t HashType = 2u << 24;
constexpr uint32_t Relocatable = 1u << 27;

uint16_t little16(const uint8_t *p)
{
    return uint16_t(p[0]) | uint16_t(p[1]) << 8;
}

uint32_t little32(const uint8_t *p)
{
    return uint32_t(little16(p)) | uint32_t(little16(p + 2)) << 16;
}

bool range(uint64_t base, uint64_t bytes)
{
    return bytes && base <= UINT64_MAX - bytes;
}

bool inside(uint64_t base, uint64_t bytes, uint64_t outer, uint64_t extent)
{
    return range(base, bytes) && range(outer, extent) && base >= outer &&
        base - outer <= extent && bytes <= extent - (base - outer);
}

bool overlap(uint64_t base, uint64_t bytes, uint64_t other, uint64_t extent)
{
    return range(base, bytes) && range(other, extent) &&
        base < other + extent && other < base + bytes;
}

void segmentPath(unsigned index, char path[24])
{
    const char prefix[] = "firmware/modem.b";
    memcpy(path, prefix, sizeof(prefix) - 1);
    size_t cursor = sizeof(prefix) - 1;
    if (index >= 100) {
        path[cursor++] = char('0' + index / 100);
    }
    path[cursor++] = char('0' + index / 10 % 10);
    path[cursor++] = char('0' + index % 10);
    path[cursor] = 0;
}

struct Segment {
    const uint8_t *data = nullptr;
    uint64_t physical = 0;
    uint32_t fileBytes = 0;
    uint32_t memoryBytes = 0;
    bool load = false;
};

struct Plan {
    const uint8_t *mdt = nullptr;
    size_t mdtBytes = 0;
    const uint8_t *hash = nullptr;
    size_t headerBytes = 0;
    size_t hashBytes = 0;
    size_t count = 0;
    uint64_t imageBytes = 0;
    bool relocatable = false;
    Segment segments[MaxHeaders];
};

void log(const Ops &ops, const Result &result)
{
    if (ops.log) {
        ops.log(ops.ctx, &result);
    }
#ifndef NABU_WIFI_MPSS_HOST_TEST
    IOLog("NabuWifiMpss: stage=%s error=%s status=%d segment=%u loaded=%llu "
        "smc=%x info=%x args=%llx/%llx/%llx/%llx convention=%u transport=%lld secure=%lld stop=%s calls=%u "
        "interrupted=%u busy=%u continuation=%llx elapsed_us=%llu "
        "metadata=%llx/%lu retained=%u pas=%u authenticated=%u state=%x ready=%u "
        "assign_submitted=%u shared_assigned=%u shared=%llx/%lu managed_base=%llx managed_bytes=%llx\n",
        stageName(result.stage), errorName(result.error), result.status,
        result.segment, (unsigned long long)result.loadedBytes,
        result.scmFunction, result.scmArgInfo,
        (unsigned long long)result.scmArgs[0], (unsigned long long)result.scmArgs[1],
        (unsigned long long)result.scmArgs[2], (unsigned long long)result.scmArgs[3],
        result.scmConvention,
        (long long)result.scm.transport, (long long)result.scm.result,
        nabuScmStopName(result.scm.stop), result.scm.calls,
        result.scm.interrupted, result.scm.busy,
        (unsigned long long)result.scm.continuation,
        (unsigned long long)result.scm.elapsed_us,
        (unsigned long long)result.metadataPhysical,
        (unsigned long)result.metadataBytes, result.metadataRetained,
        result.pasSubmitted, result.authenticated, result.smp2pState,
        result.readyObserved, result.assignmentSubmitted, result.sharedAssigned,
        (unsigned long long)result.sharedPhysical, (unsigned long)result.sharedBytes,
        (unsigned long long)result.managedBase, (unsigned long long)result.managedBytes);
#endif
}

void advance(const Ops &ops, Result &result, Stage stage)
{
    result.stage = stage;
    log(ops, result);
}

bool fail(Result &result, Error error, int status = 0)
{
    result.error = error;
    result.status = status;
    return false;
}

bool readFile(const Ops &ops, Result &result, const char *path,
    const uint8_t **data, size_t *bytes)
{
    *data = nullptr;
    *bytes = 0;
    int status = ops.getFile(ops.ctx, path, data, bytes);
    if (status || !*data || !*bytes ||
        !range(uintptr_t(*data), *bytes)) {
        return fail(result, Error::Provider, status);
    }
    return true;
}

bool readPlan(const Ops &ops, Result &result, Plan &plan)
{
    size_t mdtBytes = 0;
    advance(ops, result, Stage::ReadMdt);
    if (!readFile(ops, result, "firmware/modem.mdt", &plan.mdt, &mdtBytes)) {
        return false;
    }
    plan.mdtBytes = mdtBytes;
    advance(ops, result, Stage::ValidateMdt);
    const uint8_t *mdt = plan.mdt;
    if (mdtBytes < 52 || mdtBytes > MaxMdtBytes ||
        little32(mdt) != 0x464c457f || mdt[4] != 1 || mdt[5] != 1 ||
        mdt[6] != 1 || little16(mdt + 18) != 164 ||
        little32(mdt + 20) != 1 || little16(mdt + 40) != 52 ||
        little16(mdt + 42) != 32) {
        return fail(result, Error::InvalidMdt);
    }
    const size_t phoff = little32(mdt + 28);
    plan.count = little16(mdt + 44);
    if (plan.count < 2 || plan.count > MaxHeaders || phoff < 52 ||
        phoff > mdtBytes || plan.count * 32 > mdtBytes - phoff) {
        return fail(result, Error::InvalidMdt);
    }
    const uint8_t *first = mdt + phoff;
    plan.headerBytes = little32(first + 16);
    if (little32(first) == 1 || little32(first + 4) != 0 ||
        plan.headerBytes < phoff + plan.count * 32 ||
        plan.headerBytes > mdtBytes || plan.headerBytes > MaxMetadataBytes) {
        return fail(result, Error::InvalidMdt);
    }

    size_t hashIndex = MaxHeaders;
    uint64_t minimum = UINT64_MAX;
    uint64_t maximum = 0;
    for (size_t index = 0; index < plan.count; ++index) {
        result.segment = uint32_t(index);
        const uint8_t *ph = mdt + phoff + index * 32;
        const uint32_t flags = little32(ph + 24);
        if ((flags & HashMask) == HashType) {
            if (!index || hashIndex != MaxHeaders) {
                return fail(result, Error::InvalidMdt);
            }
            hashIndex = index;
            plan.hashBytes = little32(ph + 16);
            continue;
        }
        Segment &segment = plan.segments[index];
        segment.memoryBytes = little32(ph + 20);
        if (little32(ph) != 1 || !segment.memoryBytes) {
            continue;
        }
        segment.load = true;
        segment.physical = little32(ph + 12);
        segment.fileBytes = little32(ph + 16);
        if (segment.fileBytes > segment.memoryBytes ||
            uint64_t(segment.memoryBytes) + segment.physical > UINT64_C(0x100000000)) {
            return fail(result, Error::SegmentRange);
        }
        if (segment.physical < minimum) {
            minimum = segment.physical;
        }
        const uint64_t end = (segment.physical + segment.memoryBytes + 4095) &
            ~UINT64_C(4095);
        if (end > maximum) {
            maximum = end;
        }
        plan.relocatable |= (flags & Relocatable) != 0;
    }
    if (minimum == UINT64_MAX || hashIndex == MaxHeaders || !plan.hashBytes ||
        plan.hashBytes > MaxMetadataBytes - plan.headerBytes) {
        return fail(result, Error::InvalidMdt);
    }
    /* Match the verified host load plan's page-aligned relocation base.
     * Qualcomm PAS metadata itself remains byte-for-byte unmodified. */
    minimum &= ~UINT64_C(4095);
    plan.imageBytes = maximum - minimum;
    if (!plan.imageBytes || plan.imageBytes > MpssBytes) {
        return fail(result, Error::SegmentRange);
    }
    for (size_t index = 0; index < plan.count; ++index) {
        Segment &segment = plan.segments[index];
        if (!segment.load) {
            continue;
        }
        result.segment = uint32_t(index);
        if (plan.relocatable) {
            segment.physical = MpssBase + (segment.physical - minimum);
        }
        if (!inside(segment.physical, segment.memoryBytes, MpssBase, MpssBytes)) {
            return fail(result, Error::SegmentRange);
        }
        for (size_t previous = 0; previous < index; ++previous) {
            const Segment &other = plan.segments[previous];
            if (other.load && overlap(segment.physical, segment.memoryBytes,
                other.physical, other.memoryBytes)) {
                return fail(result, Error::SegmentOverlap);
            }
        }
    }

    result.segment = uint32_t(hashIndex);
    const uint64_t hashOffset = little32(mdt + phoff + hashIndex * 32 + 4);
    if (plan.headerBytes + plan.hashBytes == mdtBytes) {
        plan.hash = mdt + plan.headerBytes;
    } else if (hashOffset <= mdtBytes && plan.hashBytes <= mdtBytes - hashOffset) {
        plan.hash = mdt + size_t(hashOffset);
    } else {
        char path[24];
        segmentPath(unsigned(hashIndex), path);
        size_t bytes = 0;
        if (!readFile(ops, result, path, &plan.hash, &bytes)) {
            return false;
        }
        if (bytes != plan.hashBytes) {
            return fail(result, Error::SegmentSize);
        }
    }

    advance(ops, result, Stage::ReadSegments);
    for (size_t index = 0; index < plan.count; ++index) {
        Segment &segment = plan.segments[index];
        if (!segment.load || !segment.fileBytes) {
            continue;
        }
        result.segment = uint32_t(index);
        char path[24];
        segmentPath(unsigned(index), path);
        size_t bytes = 0;
        if (!readFile(ops, result, path, &segment.data, &bytes)) {
            return false;
        }
        if (bytes != segment.fileBytes) {
            return fail(result, Error::SegmentSize);
        }
    }
    result.segment = UINT32_MAX;
    return true;
}

/* Reserved mappings can be Device memory. Use aligned volatile word stores
 * and exact byte tails, including non-word-sized files and BSS boundaries.
 * libc memcpy/memset may issue unaligned/vector stores on these mappings. */
void writeMemory(uint8_t *destination, const uint8_t *source, size_t bytes)
{
    volatile uint8_t *out = destination;
    while (bytes && (uintptr_t(out) & 3)) {
        *out++ = source ? *source++ : 0;
        --bytes;
    }
    while (bytes >= 4) {
        *reinterpret_cast<volatile uint32_t *>(out) = source ? little32(source) : 0;
        out += 4;
        if (source) {
            source += 4;
        }
        bytes -= 4;
    }
    while (bytes) {
        *out++ = source ? *source++ : 0;
        --bytes;
    }
}

bool regionValid(const Region &region, uint64_t physical, size_t bytes)
{
    return region.handle && region.data && region.physical == physical &&
        region.bytes == bytes && range(uintptr_t(region.data), region.bytes);
}

bool aliasesInputs(const Region &region, const Plan &plan)
{
    const uint64_t address = uintptr_t(region.data);
    if (overlap(address, region.bytes, uintptr_t(plan.mdt), plan.mdtBytes) ||
        overlap(address, region.bytes, uintptr_t(plan.hash), plan.hashBytes)) {
        return true;
    }
    for (size_t index = 0; index < plan.count; ++index) {
        const Segment &segment = plan.segments[index];
        if (segment.data && overlap(address, region.bytes,
            uintptr_t(segment.data), segment.fileBytes)) {
            return true;
        }
    }
    return false;
}

bool callScm(const Ops &ops, const Platform &platform, Result &result,
    Stage stage, uint32_t function, uint32_t info,
    uint64_t a, uint64_t b, uint64_t c, int64_t expected = 0)
{
    result.scmFunction = function;
    result.scmArgInfo = info;
    result.scmArgs[0] = a;
    result.scmArgs[1] = b;
    result.scmArgs[2] = c;
    result.scmArgs[3] = 0;
    result.scm = NabuScmReply{};
    result.error = Error::None;
    result.status = 0;
    advance(ops, result, stage);
    result.scm = nabuScmCall(platform.scm, function, info, a, b, c);
    if (result.scm.stop != NabuScmStop::Complete) {
        fail(result, Error::ScmIncomplete, int(result.scm.stop));
    } else if (result.scm.transport) {
        fail(result, Error::ScmTransport, int(result.scm.transport));
    } else if (result.scm.result != expected) {
        fail(result, Error::ScmSecure, int(result.scm.result));
    }
    log(ops, result);
    return result.error == Error::None;
}

bool waitReady(const Ops &ops, const Platform &platform, Result &result)
{
    advance(ops, result, Stage::WaitReady);
    uint64_t start = 0;
    int status = platform.scm.now_us(platform.scm.cookie, &start);
    if (status) {
        return fail(result, Error::Clock, status);
    }
    uint64_t previous = start;
    /* A call-count bound also terminates a stalled injected/kernel clock. */
    for (unsigned poll = 0; poll < 3001; ++poll) {
        Smp2pObservation observation;
        status = ops.pollSmp2p(ops.ctx, &observation);
        if (status) {
            return fail(result, Error::Smp2p, status);
        }
        result.smp2pState = observation.state;
        if (observation.negotiated && observation.entryPresent && observation.fresh) {
            if (observation.state & FatalBit) {
                return fail(result, Error::Fatal);
            }
            if (observation.state & ReadyBit) {
                result.readyObserved = true;
                advance(ops, result, Stage::Ready);
                return true;
            }
        }
        uint64_t now = 0;
        status = platform.scm.now_us(platform.scm.cookie, &now);
        if (status || now < previous) {
            return fail(result, Error::Clock, status);
        }
        previous = now;
        if (now - start >= ReadyTimeoutUs) {
            break;
        }
        status = platform.scm.wait_us(platform.scm.cookie, 10000);
        if (status) {
            return fail(result, Error::Wait, status);
        }
    }
    return fail(result, Error::ReadyTimeout);
}

#ifndef NABU_WIFI_MPSS_HOST_TEST
uint32_t nativeBootClaim = 0;
uint32_t nativeSharedClaim = 0;

int nativeManagedWindow(void *, uint64_t *base, uint64_t *bytes)
{
    *base = gPhysBase;
    *bytes = gPhysSize;
    return 0;
}

int nativeClaim(void *)
{
    uint32_t expected = 0;
    return __atomic_compare_exchange_n(&nativeBootClaim, &expected, 1, false,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE) ? 0 : int(kIOReturnBusy);
}

int nativeClaimShared(void *)
{
    uint32_t expected = 0;
    return __atomic_compare_exchange_n(&nativeSharedClaim, &expected, 1, false,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE) ? 0 : int(kIOReturnBusy);
}

int nativeMap(void *, uint64_t physical, size_t bytes, Region *region)
{
    if (!region || !((physical == MpssBase && bytes == MpssBytes) ||
        (physical == SmemBase && bytes == SmemBytes)) ||
        !managedWindowValid(gPhysBase, gPhysSize) || overlap(physical, bytes, gPhysBase, gPhysSize)) {
        return int(kIOReturnBadArgument);
    }
    IODeviceMemory *memory = IODeviceMemory::withRange(physical, bytes);
    if (!memory) {
        return int(kIOReturnNoMemory);
    }
    IOMemoryMap *mapping = memory->map(kIOMapAnywhere | kIOMapInhibitCache);
    memory->release();
    if (!mapping) {
        return int(kIOReturnNoMemory);
    }
    if (!mapping->getVirtualAddress() || mapping->getLength() != bytes) {
        mapping->release();
        return int(kIOReturnNoSpace);
    }
    *region = {mapping, reinterpret_cast<uint8_t *>(mapping->getVirtualAddress()),
        physical, bytes};
    return 0;
}

void nativeUnmap(void *, Region *region)
{
    if (region->handle) {
        static_cast<IOMemoryMap *>(region->handle)->release();
    }
    *region = Region{};
}

int nativeAllocate(void *, size_t bytes, unsigned bits, Region *region)
{
    if (!region || !bytes || bytes > MaxOwnedBytes || (bits != 32 && bits != 64) ||
        !managedWindowValid(gPhysBase, gPhysSize)) {
        return int(kIOReturnBadArgument);
    }
    const size_t capacity = (bytes + PAGE_SIZE - 1) & ~(size_t(PAGE_SIZE) - 1);
    const uint64_t mask = bits == 32 ? UINT64_C(0xfffff000) : UINT64_C(0xfffffffff000);
    const IOOptionBits options = static_cast<IOOptionBits>(kIODirectionInOut) |
        static_cast<IOOptionBits>(kIOMemoryMapperNone) |
        kIOMemoryPhysicallyContiguous | kIOMapInhibitCache;
    IOBufferMemoryDescriptor *memory = IOBufferMemoryDescriptor::inTaskWithPhysicalMask(
        kernel_task, options, capacity, mask);
    if (!memory) {
        return int(kIOReturnNoMemory);
    }
    IOReturn status = memory->prepare();
    if (status) {
        memory->release();
        return int(status);
    }
    IOByteCount available = 0;
    const uint64_t physical = memory->getPhysicalSegment(0, &available, kIOMemoryMapperNone);
    uint8_t *data = static_cast<uint8_t *>(memory->getBytesNoCopy());
    bool valid = data && !(uintptr_t(data) & (PAGE_SIZE - 1)) &&
        !(physical & (PAGE_SIZE - 1)) && available >= PAGE_SIZE &&
        memory->getLength() == capacity &&
        inside(physical, capacity, gPhysBase, gPhysSize) &&
        (bits != 32 || inside(physical, capacity, 0, UINT64_C(0x100000000)));
    for (size_t offset = 0; valid && offset < capacity; offset += PAGE_SIZE) {
        const uint64_t current = memory->getPhysicalSegment(offset, &available,
            kIOMemoryMapperNone);
        valid = current == physical + offset && available >= PAGE_SIZE;
    }
    if (!valid) {
        (void)memory->complete();
        memory->release();
        return int(kIOReturnUnsupported);
    }
    *region = {memory, data, physical, capacity};
    return 0;
}

void nativeRelease(void *, Region *region)
{
    if (region->handle) {
        IOBufferMemoryDescriptor *memory =
            static_cast<IOBufferMemoryDescriptor *>(region->handle);
        (void)memory->complete();
        memory->release();
    }
    *region = Region{};
}

int nativePublish(void *, const Region *region, size_t offset, size_t bytes)
{
    if (!region || !region->handle || !region->data || !bytes ||
        offset > region->bytes || bytes > region->bytes - offset) {
        return int(kIOReturnBadArgument);
    }
    /* Both mappings and owned pages are explicitly non-cacheable. There is
     * no cacheable alias and no dirty CPU line to flush. Complete stores to
     * PoC before SMC/remote publication, including metadata protection. */
    __asm__ volatile("dsb sy" ::: "memory");
    return 0;
}

void nativeSmc(void *, NabuScmRegisters *regs)
{
    register uint64_t x0 __asm__("x0") = regs->x[0];
    register uint64_t x1 __asm__("x1") = regs->x[1];
    register uint64_t x2 __asm__("x2") = regs->x[2];
    register uint64_t x3 __asm__("x3") = regs->x[3];
    register uint64_t x4 __asm__("x4") = regs->x[4];
    register uint64_t x5 __asm__("x5") = regs->x[5];
    register uint64_t x6 __asm__("x6") = regs->x[6];
    register uint64_t x7 __asm__("x7") = regs->x[7];
    __asm__ volatile("dsb sy\n\tsmc #0\n\tisb" :
        "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3), "+r"(x4),
        "+r"(x5), "+r"(x6), "+r"(x7) : :
        "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
        "x16", "x17", "memory", "cc");
    regs->x[0] = x0;
    regs->x[1] = x1;
    regs->x[2] = x2;
    regs->x[3] = x3;
    regs->x[6] = x6;
}

int nativeNow(void *, uint64_t *value)
{
    uint64_t nanoseconds = 0;
    absolutetime_to_nanoseconds(mach_absolute_time(), &nanoseconds);
    *value = nanoseconds / 1000;
    return 0;
}

int nativeWait(void *, unsigned microseconds)
{
    /* Calls happen on the coordinator's worker. Let other boot work run
     * while waiting for busy SCM and SMP2P, without spinning for 30 seconds. */
    IOSleep(microseconds / 1000);
    if (microseconds % 1000) {
        IODelay(microseconds % 1000);
    }
    return 0;
}
#endif
} // namespace

bool managedWindowValid(uint64_t base, uint64_t bytes)
{
    return inside(base, bytes, XnuBase, XnuBytes) &&
        !overlap(MpssBase, MpssBytes, base, bytes) &&
        !overlap(SmemBase, SmemBytes, base, bytes) &&
        !overlap(MpssBase, MpssBytes, SmemBase, SmemBytes);
}

Result Mpss::start(const Ops &ops)
{
    Result result;
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&attempted_, &expected, 1, false,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        result.error = Error::AlreadyAttempted;
        return result;
    }
    const Platform &platform = ops.platform ? *ops.platform : nativePlatform();
    Region mpss;
    bool smemBorrowed = false;
    auto finish = [&]() -> Result {
        if (mpss.handle) {
            platform.unmap(platform.ctx, &mpss);
        }
        if (metadata_.handle && !result.pasSubmitted) {
            platform.release(platform.ctx, &metadata_);
        }
        if (smem_.handle && !smemBorrowed) {
            platform.unmap(platform.ctx, &smem_);
        }
        log(ops, result);
        return result;
    };
    advance(ops, result, Stage::ValidateOps);
    if (!ops.getFile || !ops.vote || !ops.enableXo || !ops.setModemLoadState ||
        !ops.prepareSmp2p || !ops.pollSmp2p || !platform.managedWindow ||
        !platform.claimColdBoot || !platform.map || !platform.unmap ||
        !platform.allocate || !platform.release || !platform.publish ||
        !platform.scm.invoke || !platform.scm.now_us || !platform.scm.wait_us ||
        (bool(ops.prepareRadio) != bool(ops.radioAuthAttempted))) {
        fail(result, Error::MissingOps);
        return finish();
    }
    advance(ops, result, Stage::ValidateResources);
    int status = platform.managedWindow(platform.ctx, &result.managedBase, &result.managedBytes);
    if (status || !managedWindowValid(result.managedBase, result.managedBytes)) {
        fail(result, Error::InvalidResources, status);
        return finish();
    }
    Plan plan;
    if (!readPlan(ops, result, plan)) {
        return finish();
    }
    status = platform.claimColdBoot(platform.ctx);
    if (status) {
        fail(result, Error::AlreadyAttempted, status);
        return finish();
    }
    advance(ops, result, Stage::MapSmem);
    status = platform.map(platform.ctx, SmemBase, SmemBytes, &smem_);
    if (status || !regionValid(smem_, SmemBase, SmemBytes) || aliasesInputs(smem_, plan)) {
        fail(result, Error::Mapping, status);
        return finish();
    }
    advance(ops, result, Stage::PrepareSmp2p);
    Smp2pObservation initial;
    smemBorrowed = true;
    status = ops.prepareSmp2p(ops.ctx, &smem_, &initial);
    result.smp2pState = initial.state;
    if (status) {
        fail(result, Error::Smp2p, status);
        return finish();
    }
    if (initial.entryPresent && (initial.state & (ReadyBit | FatalBit))) {
        fail(result, Error::AlreadyRunning);
        return finish();
    }
    advance(ops, result, Stage::VoteCx);
    status = ops.vote(ops.ctx, "cx.lvl", ProxyLevel);
    if (status) {
        fail(result, Error::Power, status);
        return finish();
    }
    advance(ops, result, Stage::VoteMss);
    status = ops.vote(ops.ctx, "mss.lvl", ProxyLevel);
    if (status) {
        fail(result, Error::Power, status);
        return finish();
    }
    advance(ops, result, Stage::EnableXo);
    status = ops.enableXo(ops.ctx);
    if (status) {
        fail(result, Error::Power, status);
        return finish();
    }

    uint32_t pasBase = 0x42000200;
    if (callScm(ops, platform, result, Stage::ProbeScm64,
        0xc2000601, 1, 0x02000601, 0, 0, 1)) {
        result.scmConvention = 64;
    } else {
        if (result.scm.stop != NabuScmStop::Complete) {
            return finish();
        }
        if (!callScm(ops, platform, result, Stage::ProbeScm32,
            0x82000601, 1, 0x02000601, 0, 0, 1)) {
            if (result.scm.stop == NabuScmStop::Complete) {
                result.error = Error::ScmConvention;
            }
            return finish();
        }
        result.scmConvention = 32;
        pasBase = 0x02000200;
    }
    if (ops.prepareRadio) {
        if (!callScm(ops, platform, result, Stage::PasShutdown,
                     pasBase | 6, 1, PasId, 0, 0)) return finish();
        result.radioQuiesced = true;
        advance(ops, result, Stage::PrepareRadio);
        status = ops.prepareRadio(ops.ctx);
        if (status) {
            fail(result, Error::Radio, status);
            return finish();
        }
    }
    advance(ops, result, Stage::AllocateMetadata);
    result.metadataBytes = plan.headerBytes + plan.hashBytes;
    const size_t capacity = (result.metadataBytes + 4095) & ~size_t(4095);
    status = platform.allocate(platform.ctx, capacity, result.scmConvention, &metadata_);
    if (status || !metadata_.handle || !metadata_.data || metadata_.bytes < capacity ||
        metadata_.bytes > MaxMetadataBytes || (metadata_.physical & 4095) ||
        (metadata_.bytes & 4095) || (uintptr_t(metadata_.data) & 4095) ||
        !inside(metadata_.physical, metadata_.bytes, result.managedBase, result.managedBytes) ||
        !range(uintptr_t(metadata_.data), metadata_.bytes) ||
        (result.scmConvention == 32 &&
            !inside(metadata_.physical, metadata_.bytes, 0, UINT64_C(0x100000000))) ||
        aliasesInputs(metadata_, plan) || overlap(uintptr_t(metadata_.data), metadata_.bytes,
            uintptr_t(smem_.data), smem_.bytes)) {
        fail(result, Error::Allocation, status);
        return finish();
    }
    result.metadataPhysical = metadata_.physical;
    writeMemory(metadata_.data, nullptr, metadata_.bytes);
    writeMemory(metadata_.data, plan.mdt, plan.headerBytes);
    writeMemory(metadata_.data + plan.headerBytes, plan.hash, plan.hashBytes);
    advance(ops, result, Stage::PublishMetadata);
    status = platform.publish(platform.ctx, &metadata_, 0, metadata_.bytes);
    if (status) {
        fail(result, Error::Cache, status);
        return finish();
    }
    /* From this point the metadata may be protected/in use, even if an SMC
     * returns interrupted and reaches a budget. Keep its complete descriptor
     * for this boot. No destructor or failure path frees submitted pages. */
    result.pasSubmitted = true;
    result.metadataRetained = true;
    if (!callScm(ops, platform, result, Stage::PasInitImage,
        pasBase | 1, 0x82, PasId, metadata_.physical, 0)) {
        return finish();
    }
    if (plan.relocatable && !callScm(ops, platform, result, Stage::PasMemSetup,
        pasBase | 2, 3, PasId, MpssBase, plan.imageBytes)) {
        return finish();
    }

    advance(ops, result, Stage::MapMpss);
    status = platform.map(platform.ctx, MpssBase, MpssBytes, &mpss);
    if (status || !regionValid(mpss, MpssBase, MpssBytes) || aliasesInputs(mpss, plan) ||
        overlap(uintptr_t(mpss.data), mpss.bytes, uintptr_t(metadata_.data), metadata_.bytes) ||
        overlap(uintptr_t(mpss.data), mpss.bytes, uintptr_t(smem_.data), smem_.bytes)) {
        fail(result, Error::Mapping, status);
        return finish();
    }
    for (size_t index = 0; index < plan.count; ++index) {
        const Segment &segment = plan.segments[index];
        if (!segment.load) {
            continue;
        }
        result.segment = uint32_t(index);
        advance(ops, result, Stage::LoadSegments);
        const size_t offset = size_t(segment.physical - MpssBase);
        uint8_t *destination = mpss.data + offset;
        writeMemory(destination, segment.data, segment.fileBytes);
        writeMemory(destination + segment.fileBytes, nullptr,
            segment.memoryBytes - segment.fileBytes);
        advance(ops, result, Stage::PublishSegments);
        status = platform.publish(platform.ctx, &mpss, offset, segment.memoryBytes);
        if (status) {
            fail(result, Error::Cache, status);
            return finish();
        }
        result.loadedBytes += segment.fileBytes;
    }
    result.segment = UINT32_MAX;
    advance(ops, result, Stage::SignalAop);
    status = ops.setModemLoadState(ops.ctx);
    if (status) {
        fail(result, Error::Aop, status);
        return finish();
    }
    if (ops.radioAuthAttempted) {
        result.radioQuiesced = false;
        ops.radioAuthAttempted(ops.ctx);
    }
    if (!callScm(ops, platform, result, Stage::PasAuthAndReset,
        pasBase | 5, 1, PasId, 0, 0)) {
        return finish();
    }
    result.authenticated = true;
    (void)waitReady(ops, platform, result);
    return finish();
}

Result RmtfsShared::initialize(const Ops &ops)
{
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&attempted_, &expected, 1, false,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        if (expected == 2) {
            return result_;
        }
        Result busy;
        busy.error = Error::AlreadyAttempted;
        return busy;
    }
    Result result;
    const Platform &platform = ops.platform ? *ops.platform : nativePlatform();
    auto finish = [&]() -> Result {
        if (!result.assignmentSubmitted) {
            if (parameters_.handle) platform.release(platform.ctx, &parameters_);
            if (storage_.handle) platform.release(platform.ctx, &storage_);
        }
        log(ops, result);
        result_ = result;
        __atomic_store_n(&attempted_, 2, __ATOMIC_RELEASE);
        return result;
    };
    advance(ops, result, Stage::ValidateOps);
    if (!platform.managedWindow || !platform.claimShared || !platform.allocate || !platform.release ||
        !platform.publish || !platform.scm.invoke || !platform.scm.now_us ||
        !platform.scm.wait_us) {
        fail(result, Error::MissingOps);
        return finish();
    }
    advance(ops, result, Stage::ValidateResources);
    int status = platform.managedWindow(platform.ctx, &result.managedBase, &result.managedBytes);
    if (status || !managedWindowValid(result.managedBase, result.managedBytes)) {
        fail(result, Error::InvalidResources, status);
        return finish();
    }
    status = platform.claimShared(platform.ctx);
    if (status) {
        fail(result, Error::AlreadyAttempted, status);
        return finish();
    }
    uint32_t function = 0x42000c16;
    if (callScm(ops, platform, result, Stage::ProbeScm64,
        0xc2000601, 1, 0x02000601, 0, 0, 1)) {
        result.scmConvention = 64;
    } else {
        if (result.scm.stop != NabuScmStop::Complete) return finish();
        if (!callScm(ops, platform, result, Stage::ProbeScm32,
            0x82000601, 1, 0x02000601, 0, 0, 1)) {
            if (result.scm.stop == NabuScmStop::Complete) result.error = Error::ScmConvention;
            return finish();
        }
        result.scmConvention = 32;
        function = 0x02000c16;
    }
    advance(ops, result, Stage::AllocateShared);
    /* The protocol carries 32-bit physical iovec entries. Keep the whole
     * allocation below 4 GiB, including two owned 4 KiB guard extents. */
    status = platform.allocate(platform.ctx, RmtfsSharedBytes + 8192, 32, &storage_);
    if (status || !storage_.handle || !storage_.data ||
        (storage_.physical & 4095) || (uintptr_t(storage_.data) & 4095) ||
        (storage_.bytes & 4095) || storage_.bytes < RmtfsSharedBytes + 8192 ||
        storage_.bytes > MaxOwnedBytes ||
        !inside(storage_.physical, storage_.bytes, result.managedBase, result.managedBytes) ||
        !inside(storage_.physical, storage_.bytes, 0, UINT64_C(0x100000000)) ||
        !range(uintptr_t(storage_.data), storage_.bytes)) {
        fail(result, Error::Allocation, status);
        return finish();
    }
    shared_ = {storage_.handle, storage_.data + 4096,
        storage_.physical + 4096, RmtfsSharedBytes};
    result.sharedPhysical = shared_.physical;
    result.sharedBytes = shared_.bytes;
    status = platform.allocate(platform.ctx, 4096, result.scmConvention, &parameters_);
    if (status || !parameters_.handle || !parameters_.data || parameters_.bytes < 4096 ||
        parameters_.bytes > MaxMetadataBytes || (parameters_.bytes & 4095) ||
        (parameters_.physical & 4095) || (uintptr_t(parameters_.data) & 4095) ||
        !inside(parameters_.physical, parameters_.bytes, result.managedBase, result.managedBytes) ||
        !range(uintptr_t(parameters_.data), parameters_.bytes) ||
        (result.scmConvention == 32 &&
            !inside(parameters_.physical, parameters_.bytes, 0, UINT64_C(0x100000000))) ||
        overlap(parameters_.physical, parameters_.bytes, storage_.physical, storage_.bytes) ||
        overlap(uintptr_t(parameters_.data), parameters_.bytes,
            uintptr_t(storage_.data), storage_.bytes)) {
        fail(result, Error::Allocation, status);
        return finish();
    }
    writeMemory(storage_.data, nullptr, storage_.bytes);
    writeMemory(parameters_.data, nullptr, parameters_.bytes);
    uint8_t arguments[544]{};
    auto put32 = [&](size_t offset, uint32_t value) {
        for (unsigned byte = 0; byte < 4; ++byte) {
            arguments[offset + byte] = uint8_t(value >> (byte * 8));
        }
    };
    auto put64 = [&](size_t offset, uint64_t value) {
        for (unsigned byte = 0; byte < 8; ++byte) {
            arguments[offset + byte] = uint8_t(value >> (byte * 8));
        }
    };
    put64(0, shared_.physical);
    put64(8, shared_.bytes);
    put32(64, 3); // Source HLOS VMID.
    put32(128, 3); put32(132, 6); // Destination HLOS, RW.
    put32(152, 15); put32(156, 6); // Destination MSS_MSA, RW.
    /* struct dest_vm_and_perm_info is 24 bytes, including zero context and
     * size/padding. Extended argument width follows the probed convention. */
    if (result.scmConvention == 64) {
        put64(512, 4); put64(520, parameters_.physical + 128);
        put64(528, 48); put64(536, 0);
    } else {
        put32(512, 4); put32(516, uint32_t(parameters_.physical + 128));
        put32(520, 48); put32(524, 0);
    }
    writeMemory(parameters_.data, arguments, sizeof(arguments));
    result.metadataPhysical = parameters_.physical;
    result.metadataBytes = sizeof(arguments);
    advance(ops, result, Stage::PublishShared);
    status = platform.publish(platform.ctx, &storage_, 0, storage_.bytes);
    if (!status) status = platform.publish(platform.ctx, &parameters_, 0, parameters_.bytes);
    if (status) {
        fail(result, Error::Cache, status);
        return finish();
    }
    result.scmFunction = function;
    result.scmArgInfo = 0x1117;
    result.scmArgs[0] = parameters_.physical;
    result.scmArgs[1] = 16;
    result.scmArgs[2] = parameters_.physical + 64;
    result.scmArgs[3] = parameters_.physical + 512;
    result.scm = NabuScmReply{};
    result.assignmentSubmitted = true;
    result.metadataRetained = true;
    advance(ops, result, Stage::AssignShared);
    result.scm = NabuWifiPas::assign(platform.scm, function, parameters_.physical,
        parameters_.physical + 64, parameters_.physical + 512);
    if (result.scm.stop != NabuScmStop::Complete) {
        fail(result, Error::ScmIncomplete, int(result.scm.stop));
    } else if (result.scm.transport) {
        fail(result, Error::ScmTransport, int(result.scm.transport));
    } else if (result.scm.result) {
        fail(result, Error::ScmSecure, int(result.scm.result));
    } else {
        result.sharedAssigned = true;
        advance(ops, result, Stage::SharedReady);
    }
    return finish();
}

Result MsaAssignment::assign(const Ops &ops, uint64_t address, uint32_t bytes, bool secure)
{
    for (uint32_t index = 0; index < count_; ++index) {
        const Record &record = records_[index];
        if (record.address == address && record.bytes == bytes && record.secure == secure) {
            return record.result;
        }
    }
    Result result;
    if (count_ == 2) {
        result.error = Error::AlreadyAttempted;
        return result;
    }
    const Platform &platform = ops.platform ? *ops.platform : nativePlatform();
    Region parameters;
    auto finish = [&]() -> Result {
        if (!result.assignmentSubmitted && parameters.handle) {
            platform.release(platform.ctx, &parameters);
        }
        log(ops, result);
        if (result.assignmentSubmitted) {
            records_[count_].address = address;
            records_[count_].bytes = bytes;
            records_[count_].secure = secure;
            records_[count_].result = result;
            parameters_[count_] = parameters;
            ++count_;
        }
        return result;
    };
    advance(ops, result, Stage::ValidateOps);
    if (!platform.managedWindow || !platform.allocate || !platform.release || !platform.publish ||
        !platform.scm.invoke || !platform.scm.now_us || !platform.scm.wait_us) {
        fail(result, Error::MissingOps);
        return finish();
    }
    advance(ops, result, Stage::ValidateResources);
    int status = platform.managedWindow(platform.ctx, &result.managedBase, &result.managedBytes);
    if (status || !managedWindowValid(result.managedBase, result.managedBytes) ||
        !inside(address, bytes, MsaBase, MsaBytes) || (address & 4095) || (bytes & 4095) ||
        overlap(address, bytes, result.managedBase, result.managedBytes)) {
        fail(result, Error::InvalidResources, status);
        return finish();
    }
    result.sharedPhysical = address;
    result.sharedBytes = bytes;
    uint32_t function = 0x42000c16;
    if (callScm(ops, platform, result, Stage::ProbeScm64,
        0xc2000601, 1, 0x02000601, 0, 0, 1)) {
        result.scmConvention = 64;
    } else {
        if (result.scm.stop != NabuScmStop::Complete) return finish();
        if (!callScm(ops, platform, result, Stage::ProbeScm32,
            0x82000601, 1, 0x02000601, 0, 0, 1)) {
            if (result.scm.stop == NabuScmStop::Complete) result.error = Error::ScmConvention;
            return finish();
        }
        result.scmConvention = 32;
        function = 0x02000c16;
    }
    advance(ops, result, Stage::AllocateMetadata);
    status = platform.allocate(platform.ctx, 4096, result.scmConvention, &parameters);
    if (status || !parameters.handle || !parameters.data || parameters.bytes < 4096 ||
        parameters.bytes > MaxMetadataBytes || (parameters.bytes & 4095) ||
        (parameters.physical & 4095) || (uintptr_t(parameters.data) & 4095) ||
        !inside(parameters.physical, parameters.bytes, result.managedBase, result.managedBytes) ||
        !range(uintptr_t(parameters.data), parameters.bytes) ||
        (result.scmConvention == 32 &&
            !inside(parameters.physical, parameters.bytes, 0, UINT64_C(0x100000000)))) {
        fail(result, Error::Allocation, status);
        return finish();
    }
    writeMemory(parameters.data, nullptr, parameters.bytes);
    uint8_t arguments[544]{};
    auto put32 = [&](size_t offset, uint32_t value) {
        for (unsigned byte = 0; byte < 4; ++byte) {
            arguments[offset + byte] = uint8_t(value >> (byte * 8));
        }
    };
    auto put64 = [&](size_t offset, uint64_t value) {
        for (unsigned byte = 0; byte < 8; ++byte) {
            arguments[offset + byte] = uint8_t(value >> (byte * 8));
        }
    };
    static const uint32_t destinations[3] = {15, 24, 25};
    const unsigned count = secure ? 2 : 3;
    put64(0, address);
    put64(8, bytes);
    put32(64, 3); // Source HLOS VMID. HLOS is deliberately not a destination.
    for (unsigned index = 0; index < count; ++index) {
        put32(128 + 24 * index, destinations[index]);
        put32(132 + 24 * index, 6); // RW.
    }
    if (result.scmConvention == 64) {
        put64(512, 4); put64(520, parameters.physical + 128);
        put64(528, 24 * count); put64(536, 0);
    } else {
        put32(512, 4); put32(516, uint32_t(parameters.physical + 128));
        put32(520, 24 * count); put32(524, 0);
    }
    writeMemory(parameters.data, arguments, sizeof(arguments));
    result.metadataPhysical = parameters.physical;
    result.metadataBytes = sizeof(arguments);
    advance(ops, result, Stage::PublishShared);
    status = platform.publish(platform.ctx, &parameters, 0, parameters.bytes);
    if (status) {
        fail(result, Error::Cache, status);
        return finish();
    }
    result.scmFunction = function;
    result.scmArgInfo = 0x1117;
    result.scmArgs[0] = parameters.physical;
    result.scmArgs[1] = 16;
    result.scmArgs[2] = parameters.physical + 64;
    result.scmArgs[3] = parameters.physical + 512;
    result.scm = NabuScmReply{};
    result.assignmentSubmitted = true;
    result.metadataRetained = true;
    advance(ops, result, Stage::AssignMsa);
    result.scm = NabuWifiPas::assign(platform.scm, function, parameters.physical,
        parameters.physical + 64, parameters.physical + 512);
    if (result.scm.stop != NabuScmStop::Complete) {
        fail(result, Error::ScmIncomplete, int(result.scm.stop));
    } else if (result.scm.transport) {
        fail(result, Error::ScmTransport, int(result.scm.transport));
    } else if (result.scm.result) {
        fail(result, Error::ScmSecure, int(result.scm.result));
    } else {
        result.msaAssigned = true;
        advance(ops, result, Stage::MsaAssigned);
    }
    return finish();
}

bool RmtfsShared::region(Region *out) const
{
    if (!out) return false;
    *out = Region{};
    if (__atomic_load_n(&attempted_, __ATOMIC_ACQUIRE) != 2 || !result_.sharedAssigned) {
        return false;
    }
    *out = shared_;
    return true;
}

const char *stageName(Stage stage)
{
    static const char *const names[] = {
        "idle", "validate-ops", "validate-resources", "read-mdt", "validate-mdt",
        "read-segments", "map-smem", "prepare-smp2p", "vote-cx", "vote-mss",
        "enable-xo", "probe-scm64", "probe-scm32", "allocate-metadata",
        "publish-metadata", "pas-init-image", "pas-mem-setup", "map-mpss",
        "load-segments", "publish-segments", "signal-aop", "pas-auth-and-reset",
        "wait-ready", "ready", "allocate-shared", "publish-shared", "assign-shared", "shared-ready",
        "assign-msa", "msa-assigned", "pas-shutdown", "prepare-radio"
    };
    const uint32_t index = uint32_t(stage);
    return index < sizeof(names) / sizeof(names[0]) ? names[index] : "invalid-stage";
}

const char *errorName(Error error)
{
    static const char *const names[] = {
        "none", "already-attempted", "missing-ops", "invalid-resources", "provider",
        "invalid-mdt", "segment-size", "segment-range", "segment-overlap",
        "mapping", "allocation", "cache", "smp2p", "already-running", "power",
        "scm-convention", "scm-transport", "scm-secure", "scm-incomplete", "aop",
        "clock", "wait", "fatal", "ready-timeout", "radio"
    };
    const uint32_t index = uint32_t(error);
    return index < sizeof(names) / sizeof(names[0]) ? names[index] : "invalid-error";
}

#ifndef NABU_WIFI_MPSS_HOST_TEST
const Platform &nativePlatform()
{
    static const Platform platform{
        nullptr, nativeManagedWindow, nativeClaim, nativeMap, nativeUnmap,
        nativeAllocate, nativeRelease, nativePublish,
        {nullptr, nativeSmc, nativeNow, nativeWait}, nativeClaimShared
    };
    return platform;
}

namespace {
RmtfsShared nativeShared;
MsaAssignment nativeMsa;
}

Result nativeAssignMsaRegion(uint64_t address, uint32_t bytes, bool secure)
{
    const Ops ops{};
    return nativeMsa.assign(ops, address, bytes, secure);
}

Result nativeRmtfsSharedRegion(Region *out)
{
    if (!out) {
        Result invalid;
        invalid.stage = Stage::ValidateOps;
        invalid.error = Error::MissingOps;
        invalid.status = int(kIOReturnBadArgument);
        return invalid;
    }
    const Ops ops{};
    Result result = nativeShared.initialize(ops);
    (void)nativeShared.region(out);
    return result;
}

int nativeRmtfsSharedSync(void *, void *data, size_t bytes, bool)
{
    Region shared;
    if (!nativeShared.region(&shared) || !data ||
        !inside(uintptr_t(data), bytes, uintptr_t(shared.data), shared.bytes)) {
        return int(kIOReturnBadArgument);
    }
    __asm__ volatile("dsb sy" ::: "memory");
    return 0;
}
#endif
} // namespace NabuWifiMpss
