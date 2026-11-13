/* SPDX-License-Identifier: BSD-2-Clause-Patent */
/* Derived from buhuo666/XIAOMI-PAD-5_nabu-on-IOS at
 * 56c7364f5c083583b07eea24dded38a9ee932e5f,
 * patches/nabu-wireless/NabuWlanDma.{h,cpp} (BSD-2-Clause-Patent).
 * ArmSmmu4K remains a separately licensed MIT dependency.
 */
#ifndef NABU_WIFI_DMA_H
#define NABU_WIFI_DMA_H

#include <stddef.h>
#include <stdint.h>

namespace NabuWifiDma {
struct View {
    void *cpu = nullptr;
    uint32_t iova = 0;
    size_t bytes = 0;
};
constexpr int RadioUnavailable = -1;
int prepareRadio();
/* Called just after successful real PAS_SHUTDOWN(PAS 4), using the selected
 * SCM convention with ARC/XO held, before PAS_AUTH_RESET submission. */
int activateRadioAfterPasStop();
void radioAuthAttempted();
bool observeRadio();
/* Borrow only while Active and fault-free. Runtime stops its driver IRQ and
 * drains its work before any retainedStop() route change. */
bool radioMemory(View &);
bool publishRadioMemory(size_t offset, size_t bytes);
/* Records a nonzero failure and retains the lease/memory. True means retained.
 * This records no route writes and performs no driver or PAS operations. */
bool retainRadioFault(int status);
}

#if (defined(NABU_WIFI_RADIO) && NABU_WIFI_RADIO) || defined(NABU_WIFI_DMA_HOST_TEST)
#include <string.h>
#include "../usb/NabuUsbSmmu.h"
#include "../gpu/upstream/ArmSmmu4K/ArmSmmu4KAudit.h"
#include "../gpu/upstream/ArmSmmu4K/ArmSmmu4KStreams.h"

namespace NabuWifiDma {
constexpr size_t ArenaBytes = 44u << 20;
constexpr size_t TableBytes = 128u << 10;
constexpr size_t AllocationAlignment = 16384;
constexpr uint64_t IovaBase = UINT64_C(0xa0000000);
constexpr uint64_t SmmuBase = UINT64_C(0x15000000);
constexpr size_t SmmuBytes = 0x100000;
constexpr uint16_t FirstSid = 0x640;
constexpr unsigned StreamCount = 2;

struct Memory {
    void *cpu = nullptr;
    uint64_t physical = 0;
    size_t bytes = 0;
    void *nativeDescriptor = nullptr;
};
struct Platform {
    void *cookie = nullptr;
    int (*managedWindow)(void *, uint64_t *, uint64_t *) = nullptr;
    /* Exclusive, physically contiguous pages, aligned to 16 KiB in CPU and PA
     * space. Native arena is verified NormalUncached, tables are WB. Failure
     * leaves out empty. No implicit IOMemoryMapper or additional CPU alias. */
    int (*allocate)(void *, size_t, Memory *) = nullptr;
    void (*release)(void *, Memory *) = nullptr;
    /* Native arena orders verified NormalUncached writes. WB tables require
     * real clean/invalidate to PoC. Both finish with a barrier. */
    int (*publish)(void *, const Memory *, size_t, size_t) = nullptr;
};
struct Lease {
    unsigned bank = 0;
    unsigned asid = 0;
    ArmSmmu4KStream routes[StreamCount]{};
};
struct Activation {
    void *cookie = nullptr;
    uint64_t physical = 0;
    ArmSmmu4KIo io{};
    /* Shared by EVERY apps-SMMU configuration owner, including UFS. These
     * operations run in thread context. No callback may call back into Owner.
     * A failed lock/claim must have no side effects. A successful claim holds
     * this bank/ASID/slot lease for the rest of this boot, including failures. */
    int (*lock)(void *) = nullptr;
    void (*unlock)(void *) = nullptr;
    int (*claim)(void *, const Lease *) = nullptr;
    /* Must observe powered MMIO and actually stopped WLAN masters, both at
     * activation and retained stop. Software queue emptiness is insufficient. */
    int (*mastersStopped)(void *) = nullptr;
    /* Installs real context AND global fault handling under this lease. May
     * partially install on failure, so an attempted registration is retained.
     * This module never detaches handlers or frees an attempted lease. */
    int (*installFaults)(void *, const Lease *, const ArmSmmu4KIo *) = nullptr;
};
enum class State { Empty, Prepared, Active, Retained };
enum class Stage { Idle, Window, Arena, Tables, Publish, Audit, Dependencies,
    Selection, Claim, FaultHandler, Actlr, FaultRoutes, Context, Streams,
    Observation, Stop, Release };
enum class Error { None, Argument, Busy, Allocation, Window, Memory,
    Publish, Dependency, Ufs, Lease, FaultHandler, Hardware };
struct Result {
    State state = State::Empty;
    Stage stage = Stage::Idle;
    Error error = Error::None; // First failure remains available after stop.
    Stage failureStage = Stage::Idle;
    int status = 0; // Original platform/helper status of the first failure.
    int lastStatus = 0;
    uint64_t managedBase = 0, managedBytes = 0;
    uint64_t arenaPhysical = 0, tablePhysical = 0;
    Lease lease{};
    uint32_t id0 = 0, id1 = 0, id2 = 0, scr0 = 0, globalFault = 0;
    unsigned conflictSlot = UINT32_MAX;
    uint32_t conflictSmr = 0, conflictS2cr = 0;
    uint32_t faultDirect[StreamCount]{}, faultReadback[StreamCount]{};
    bool faultEncodingQuirk = false;
    bool leaseHeld = false, faultHandlerAttempted = false;
    bool hardwareAttempted = false, stopFaulted = false;
    ArmSmmu4KResult tables{};
    ArmSmmu4KProgramResult program{};
    ArmSmmu4KStreamResult streams{};
    ArmSmmu4KAuditResult audit{};
};

/* One owner per boot. The caller keeps this object, callback cookies, MMIO
 * mapping and runtime power alive through every retained path. No destructor
 * frees DMA memory. Lifecycle calls reject concurrent/reentrant execution.
 * result() is a diagnostic reference for an externally serialized caller.
 * memory() lends the whole LinuxKPI arena only while Active and fault-free.
 * Active means SMMU attached, without CE/IRQ/FW readiness. Retained memory and
 * descriptors last for this boot, including after borrower faults.
 */
class Owner {
public:
    Owner() = default;
    Owner(const Owner &) = delete;
    Owner &operator=(const Owner &) = delete;
    bool prepare(const Platform &);
    bool activate(const Activation &);
    bool memory(View &);
    bool publish(size_t offset, size_t bytes);
    bool observe(); // Full masked-conflict scan and real register observation.
    bool retainedStop(); // Fault verified owned routes, retain all resources.
    bool retainFault(int status = ArmSmmu4KFault); // Thread delivery of a sticky fault or invalidated lease.
    bool releasePrepared(); // Only before any lease/registration/MMIO attempt.
    const Result &result() const { return result_; }
private:
    bool enter();
    void leave();
    bool fail(Error, int);
    bool prepareMemory();
    bool select();
    bool audit();
    bool ufsUnchanged();
    bool selectionUnchanged();
    bool faultRoutes();
    bool activateLocked();
    bool observeLocked();
    bool stopLocked();
    void releaseMemory();
    uint32_t read(size_t);
    bool write(size_t, uint32_t);
    void configureIo();
    static int readTable(void *, uint64_t, uint64_t *);
    unsigned entered_ = 0;
    Platform platform_{};
    Activation activation_{};
    ArmSmmu4KIo io_{};
    Memory arena_{}, tables_{};
    ArmSmmu4KRange range_{};
    ArmSmmu4KConfig mapping_{};
    ArmSmmu4KContextConfig context_{};
    ArmSmmu4KStreamState streams_{};
    Result result_{};
    size_t bankOffset_ = 0;
    uint32_t oldSmr_[StreamCount]{}, oldS2cr_[StreamCount]{};
    unsigned ufsSlot_ = 0, ufsBank_ = 0;
    uint32_t ufsSmr_ = 0, ufsS2cr_ = 0;
    uint32_t ufsRegisters_[10]{};
    uint32_t ufsCbar_ = 0, ufsCba2r_ = 0;
    uint32_t selectedSctlr_ = 0, selectedActlr_ = 0;
    bool readFailed_ = false;
};

/* Current 17.7 IOKit allocation/cache and boot-retained activation adapter.
 * An empty injected Activation fails before MMIO or lease acquisition. */
const Platform &nativePlatform();
Owner *radioOwner();
inline constexpr uint8_t SourceFdtSha256[32] = {
    0x21,0xd4,0x35,0x5e,0xba,0x46,0xbc,0xd6,0x04,0x3d,0x3f,0x4b,0x92,0x05,0x0a,0x7b,
    0xba,0xc4,0xf9,0x47,0x62,0x07,0xc7,0xc5,0xaf,0xea,0x61,0x4e,0xc5,0x75,0x13,0xc9
};
inline bool sourceDigestMatches(const void *data, size_t bytes)
{
    return data && bytes == sizeof(SourceFdtSha256) && !memcmp(data, SourceFdtSha256, bytes);
}
struct IrqSpec { uint32_t type, spi, flags; };
inline constexpr IrqSpec GlobalFaultIrq{0, 65, 4};
/* All 80 actual context specs after the FDT's one global spec. This bound
 * PDC transparent route uses GIC INTID = SPI + 32, flags 4 means level. */
inline constexpr IrqSpec ContextFaultIrqs[80] = {
    {0,97,4},{0,98,4},{0,99,4},{0,100,4},{0,101,4},{0,102,4},{0,103,4},{0,104,4},
    {0,105,4},{0,106,4},{0,107,4},{0,108,4},{0,109,4},{0,110,4},{0,111,4},{0,112,4},
    {0,113,4},{0,114,4},{0,115,4},{0,116,4},{0,117,4},{0,118,4},{0,181,4},{0,182,4},
    {0,183,4},{0,184,4},{0,185,4},{0,186,4},{0,187,4},{0,188,4},{0,189,4},{0,190,4},
    {0,191,4},{0,192,4},{0,315,4},{0,316,4},{0,317,4},{0,318,4},{0,319,4},{0,320,4},
    {0,321,4},{0,322,4},{0,323,4},{0,324,4},{0,325,4},{0,326,4},{0,327,4},{0,328,4},
    {0,329,4},{0,330,4},{0,331,4},{0,332,4},{0,333,4},{0,334,4},{0,335,4},{0,336,4},
    {0,337,4},{0,338,4},{0,339,4},{0,340,4},{0,341,4},{0,342,4},{0,343,4},{0,344,4},
    {0,345,4},{0,395,4},{0,396,4},{0,397,4},{0,398,4},{0,399,4},{0,400,4},{0,401,4},
    {0,402,4},{0,403,4},{0,404,4},{0,405,4},{0,406,4},{0,407,4},{0,408,4},{0,409,4}
};
struct FaultRecord {
    uint64_t sequence = 0, address = 0, dropped = 0;
    uint32_t status = 0, syndrome0 = 0, syndrome1 = 0, syndrome2 = 0;
    uint32_t ackReadback = 0;
    uint32_t sidField = 0, bank = UINT32_MAX;
    int ioStatus = 0;
};
/* Bounded latest-snapshot recorder. Payload accesses are atomic, ISR never
 * waits. Sequence gaps and dropped() expose overwrite/concurrent-writer loss. */
class FaultLatch {
public:
    void record(const FaultRecord &);
    bool read(FaultRecord &) const;
    uint64_t dropped() const { return __atomic_load_n(&dropped_, __ATOMIC_ACQUIRE); }
private:
    unsigned writing_ = 0;
    uint64_t version_ = 0, count_ = 0, dropped_ = 0, address_ = 0;
    uint32_t status_ = 0, syndrome0_ = 0, syndrome1_ = 0, syndrome2_ = 0;
    uint32_t sid_ = 0, bank_ = UINT32_MAX;
    uint32_t ackReadback_ = 0;
    int ioStatus_ = 0;
};
class RadioGate {
public:
    bool confirmPasStop();
    void authAttempted();
    bool stopped() const { return __atomic_load_n(&stopped_, __ATOMIC_ACQUIRE) != 0; }
private:
    unsigned stopped_ = 0, authAttempted_ = 0;
};
struct NativeLease {
    bool held = false;
    Lease lease{};
    int claim(const ArmSmmu4KIo &, const Lease &); // Under shared apps lock.
};
struct FaultHandler {
    ArmSmmu4KIo io{};
    FaultLatch *latch = nullptr;
    unsigned bank = UINT32_MAX;
    size_t contextOffset = 0;
    unsigned faulted = 0; // Sticky, independently of W1C acknowledgment.
};
void captureGlobalFault(void *);
void captureContextFault(void *);
struct IrqOps {
    void *cookie = nullptr;
    int (*attach)(void *, uint32_t, bool, void (*)(void *), void *, uint32_t *, uint64_t *) = nullptr;
};
struct FaultIrqs {
    FaultLatch global, context;
    FaultHandler globalHandler, contextHandler;
    bool attempted = false;
    int status = ArmSmmu4KArgument;
    uint32_t globalReadback = 0, contextReadback = 0;
    uint64_t globalRouter = 0, contextRouter = 0;
    int install(const IrqOps &, const ArmSmmu4KIo &, const Lease &);
};
} // namespace NabuWifiDma

extern "C" int nabu_wifi_smmu_lock(void);
extern "C" void nabu_wifi_smmu_unlock(void);
/* Thread consumer of faults from ALL SIDs. sidField is GFSYNR1's raw low
 * 16-bit field without WLAN attribution. False leaves the cursor unchanged. */
extern "C" bool nabu_wifi_smmu_global_fault_read(uint64_t *after, NabuWifiDma::FaultRecord *out);

namespace NabuWifiDma {
namespace detail {
inline constexpr uint64_t DramBase = UINT64_C(0xc0000000);
inline constexpr uint64_t DramBytes = UINT64_C(0x140000000);
inline constexpr uint32_t Fault = 2u << 16;
inline constexpr unsigned PollBudget = 10000;
inline constexpr size_t UfsOffsets[] = {0, 4, 0x10, 0x20, 0x24, 0x28, 0x2c, 0x30, 0x38, 0x3c};

inline bool inside(uint64_t address, uint64_t bytes, uint64_t base, uint64_t capacity)
{
    return bytes && address >= base && address - base < capacity &&
        bytes <= capacity - (address - base);
}

inline bool overlaps(uint64_t first, uint64_t firstBytes, uint64_t second, uint64_t secondBytes)
{
    return first <= second ? second - first < firstBytes : first - second < secondBytes;
}

inline bool validMemory(const Memory &memory, size_t bytes, uint64_t base, uint64_t capacity)
{
    return memory.cpu && memory.bytes == bytes &&
        !(uintptr_t(memory.cpu) & (AllocationAlignment - 1)) &&
        !(memory.physical & (AllocationAlignment - 1)) &&
        uintptr_t(memory.cpu) <= UINTPTR_MAX - bytes &&
        inside(memory.physical, bytes, base, capacity) &&
        inside(memory.physical, bytes, 0, UINT64_C(1) << 36);
}
template <typename Translate>
bool contiguousMemory(const Memory &memory, uint64_t base, uint64_t capacity, Translate translate)
{
    if (!validMemory(memory, memory.bytes, base, capacity)) return false;
    for (size_t offset = 0; offset < memory.bytes; offset += 4096) {
        if (translate(uintptr_t(memory.cpu) + offset) != memory.physical + offset) return false;
    }
    return true;
}
} // namespace detail

inline bool Owner::enter()
{
    unsigned expected = 0;
    return __atomic_compare_exchange_n(&entered_, &expected, 1, false,
        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}

inline void Owner::leave()
{
    __atomic_store_n(&entered_, 0, __ATOMIC_RELEASE);
}

inline bool Owner::fail(Error error, int status)
{
    result_.lastStatus = status;
    if (result_.leaseHeld) result_.state = State::Retained;
    if (result_.error == Error::None) {
        result_.error = error;
        result_.failureStage = result_.stage;
        result_.status = status;
    }
    return false;
}

inline void Owner::releaseMemory()
{
    if (tables_.cpu) platform_.release(platform_.cookie, &tables_);
    if (arena_.cpu) platform_.release(platform_.cookie, &arena_);
    tables_ = {};
    arena_ = {};
    result_.state = State::Empty;
}

inline bool Owner::prepareMemory()
{
    result_.stage = Stage::Window;
    int status = platform_.managedWindow(platform_.cookie, &result_.managedBase,
        &result_.managedBytes);
    if (status) return fail(Error::Window, status);
    if (!detail::inside(result_.managedBase, result_.managedBytes, detail::DramBase, detail::DramBytes) ||
        ((result_.managedBase | result_.managedBytes) & 4095)) {
        return fail(Error::Window, ArmSmmu4KBadRange);
    }
    result_.stage = Stage::Arena;
    status = platform_.allocate(platform_.cookie, ArenaBytes, &arena_);
    if (status) return fail(Error::Allocation, status);
    result_.arenaPhysical = arena_.physical;
    if (!detail::validMemory(arena_, ArenaBytes, result_.managedBase, result_.managedBytes)) {
        return fail(Error::Memory, ArmSmmu4KBadRange);
    }
    result_.stage = Stage::Tables;
    status = platform_.allocate(platform_.cookie, TableBytes, &tables_);
    if (status) return fail(Error::Allocation, status);
    result_.tablePhysical = tables_.physical;
    if (!detail::validMemory(tables_, TableBytes, result_.managedBase, result_.managedBytes) ||
        detail::overlaps(arena_.physical, arena_.bytes, tables_.physical, tables_.bytes) ||
        detail::overlaps(uintptr_t(arena_.cpu), arena_.bytes, uintptr_t(tables_.cpu), tables_.bytes)) {
        return fail(Error::Memory, ArmSmmu4KOverlap);
    }
    memset(arena_.cpu, 0, arena_.bytes);
    mapping_ = {32, 36, tables_.physical, ArenaBytes / 4096};
    range_ = {IovaBase, arena_.physical, ArenaBytes, ArmSmmu4KRead | ArmSmmu4KWrite, 1, 3};
    status = ArmSmmu4KBuild(&mapping_, &range_, 1, static_cast<uint64_t *>(tables_.cpu),
        TableBytes / 4096, &result_.tables);
    if (status) return fail(Error::Memory, status);
    context_ = {};
    context_.lower = &mapping_;
    context_.lower_tables = &result_.tables;
    context_.coherent_walk = 0;
    result_.stage = Stage::Publish;
    status = platform_.publish(platform_.cookie, &arena_, 0, arena_.bytes);
    if (!status) status = platform_.publish(platform_.cookie, &tables_, 0,
        result_.tables.table_pages * 4096);
    if (status) return fail(Error::Publish, status);
    return audit();
}

inline bool Owner::prepare(const Platform &platform)
{
    if (!enter()) return false;
    bool ok = false;
    if (result_.state != State::Empty) {
        fail(Error::Busy, ArmSmmu4KBusy);
    } else {
        result_ = {};
        platform_ = platform;
        if (!platform.managedWindow || !platform.allocate || !platform.release || !platform.publish) {
            fail(Error::Argument, ArmSmmu4KArgument);
        } else {
            ok = prepareMemory();
            if (ok) result_.state = State::Prepared;
            else releaseMemory();
        }
    }
    leave();
    return ok;
}

inline int Owner::readTable(void *cookie, uint64_t physical, uint64_t *value)
{
    Owner &owner = *static_cast<Owner *>(cookie);
    if (!value || (physical & 7) ||
        !detail::inside(physical, sizeof(*value), owner.tables_.physical, owner.tables_.bytes)) return -1;
    const size_t offset = size_t(physical - owner.tables_.physical);
    *value = *reinterpret_cast<const uint64_t *>(static_cast<const uint8_t *>(owner.tables_.cpu) + offset);
    return 0;
}

inline bool Owner::audit()
{
    result_.stage = Stage::Audit;
    unsigned char visited[TableBytes / 4096]{};
    ArmSmmu4KAuditRegion region{&range_, 1, TableBytes / 4096,
        TableBytes / sizeof(uint64_t), visited, sizeof(visited)};
    ArmSmmu4KAuditConfig config{{this, readTable}, &region, nullptr};
    int status = ArmSmmu4KAuditDeclaredContext(&context_, &config, &result_.audit);
    return status ? fail(Error::Memory, status) : true;
}

inline uint32_t Owner::read(size_t offset)
{
    uint32_t value = 0;
    if (io_.read32(io_.cookie, offset, &value)) readFailed_ = true;
    return value;
}

inline bool Owner::write(size_t offset, uint32_t value)
{
    if (io_.write32(io_.cookie, offset, value) || io_.barrier(io_.cookie)) {
        return fail(Error::Hardware, ArmSmmu4KIoError);
    }
    return true;
}

inline void Owner::configureIo()
{
    io_ = {this, activation_.io.register_bytes,
        [](void *cookie, size_t offset, uint32_t *value) {
            Owner &owner = *static_cast<Owner *>(cookie);
            return owner.activation_.io.read32(owner.activation_.io.cookie, offset, value);
        },
        [](void *cookie, size_t offset, uint64_t *value) {
            Owner &owner = *static_cast<Owner *>(cookie);
            return owner.activation_.io.read64(owner.activation_.io.cookie, offset, value);
        },
        [](void *cookie, size_t offset, uint32_t value) {
            Owner &owner = *static_cast<Owner *>(cookie);
            /* Qualcomm FAULT encoding is adjusted only for the two leased
             * S2CRs, after raw readback proved the quirk on invalid slots. */
            if (owner.result_.faultEncodingQuirk && value == detail::Fault) {
                for (const auto &route : owner.result_.lease.routes) {
                    if (offset == 0xc00 + 4 * route.slot) value = 1u << 16;
                }
            }
            return owner.activation_.io.write32(owner.activation_.io.cookie, offset, value);
        },
        [](void *cookie, size_t offset, uint64_t value) {
            Owner &owner = *static_cast<Owner *>(cookie);
            return owner.activation_.io.write64(owner.activation_.io.cookie, offset, value);
        },
        [](void *cookie) {
            Owner &owner = *static_cast<Owner *>(cookie);
            return owner.activation_.io.barrier(owner.activation_.io.cookie);
        }};
}

inline bool Owner::select()
{
    using namespace nabu_usb::smmu;
    result_.stage = Stage::Selection;
    Info info{};
    const auto reader = [this](uint32_t offset) { return read(offset); };
    bool supported = read_info(reader, &info, SmmuBytes);
    result_.id0 = info.idr0;
    result_.id1 = info.idr1;
    result_.id2 = info.idr2;
    result_.globalFault = info.gfsr;
    result_.scr0 = read(0);
    if (readFailed_) return fail(Error::Hardware, ArmSmmu4KIoError);
    if (!supported || info.exids || !(info.idr0 & (1u << 30)) ||
        ((FirstSid + StreamCount - 1) & ~stream_id_mask(info))) {
        return fail(Error::Hardware, ArmSmmu4KUnsupported);
    }
    if (info.gfsr) return fail(Error::Hardware, ArmSmmu4KFault);
    if ((result_.scr0 & 0x40f) != 0x406) return fail(Error::Hardware, ArmSmmu4KStateMismatch);
    Match ufs{};
    bool foundUfs = find_stream(reader, info, 0x300, &ufs);
    if (readFailed_) return fail(Error::Hardware, ArmSmmu4KIoError);
    if (!foundUfs || !ufs.exact || ufs.cbndx == 0 || ufs.cbndx >= info.num_cb) {
        return fail(Error::Ufs, ArmSmmu4KBusy);
    }
    ufsSlot_ = ufs.index;
    ufsBank_ = ufs.cbndx;
    ufsSmr_ = ufs.smr;
    ufsS2cr_ = ufs.s2cr;
    size_t ufsOffset = context_offset(info.global_pages, ufsBank_);
    for (unsigned i = 0; i < 10; ++i) ufsRegisters_[i] = read(ufsOffset + detail::UfsOffsets[i]);
    ufsCbar_ = read(kCbarBase + 4 * ufsBank_);
    ufsCba2r_ = read(kCba2rBase + 4 * ufsBank_);
    if (readFailed_) return fail(Error::Hardware, ArmSmmu4KIoError);
    if (!is_bypass_context(ufs.type, ufsRegisters_[0], ufsCbar_, ufsCba2r_)) {
        return fail(Error::Ufs, ArmSmmu4KStateMismatch);
    }
    bool used[kMaxBanks]{};
    unsigned freeCount = 0;
    for (unsigned slot = 0; slot < info.num_smr; ++slot) {
        uint32_t smr = read(kSmrBase + 4 * slot), s2cr = read(kS2crBase + 4 * slot);
        if (smr & kSmrValid) {
            uint32_t mask = (smr >> 16) & 0x7fff;
            for (unsigned n = 0; n < StreamCount; ++n) {
                if (((FirstSid + n) ^ smr) & ~mask & stream_id_mask(info)) continue;
                result_.conflictSlot = slot;
                result_.conflictSmr = smr;
                result_.conflictS2cr = s2cr;
                return fail(Error::Lease, ArmSmmu4KBusy);
            }
            if ((s2cr & kS2crTypeMask) == 0) {
                unsigned bank = s2cr & kS2crCbndxMask;
                if (bank >= info.num_cb) return fail(Error::Hardware, ArmSmmu4KBadRange);
                used[bank] = true;
            }
        } else if (freeCount < StreamCount) {
            result_.lease.routes[freeCount] = {slot, uint16_t(FirstSid + freeCount)};
            oldSmr_[freeCount] = smr;
            oldS2cr_[freeCount] = s2cr;
            ++freeCount;
        }
    }
    if (readFailed_) return fail(Error::Hardware, ArmSmmu4KIoError);
    if (freeCount != StreamCount) return fail(Error::Lease, ArmSmmu4KCapacity);
    for (unsigned bank = info.num_cb - 1; bank > 0 && bank >= info.num_s2_cb; --bank) {
        if (used[bank] || bank == ufsBank_) continue;
        size_t offset = context_offset(info.global_pages, bank);
        /* A disabled unreferenced bank may contain firmware's inert register
         * image. ACTLR 0/3 follows donor's recorded platform initialization.
         * The external lease still has to establish real software ownership. */
        uint32_t sctlr = read(offset), actlr = read(offset + 4);
        if ((sctlr & 1) || (actlr != 0 && actlr != 3)) continue;
        unsigned asid = bank + 1;
        bool collision = false;
        for (unsigned other = 0; other < info.num_cb; ++other) {
            size_t at = context_offset(info.global_pages, other);
            if (read(at) & 1) {
                if ((read(at + 0x24) >> 16) == asid ||
                    (read(at + 0x2c) >> 16) == asid) collision = true;
            }
        }
        if (collision) continue;
        if (readFailed_) return fail(Error::Hardware, ArmSmmu4KIoError);
        result_.lease.bank = bank;
        result_.lease.asid = asid;
        selectedSctlr_ = sctlr;
        selectedActlr_ = actlr;
        bankOffset_ = offset;
        context_.asid = asid;
        context_.id0 = info.idr0;
        context_.id2 = info.idr2;
        ArmSmmu4KContextImage image{};
        int status = ArmSmmu4KEncodeContext(&context_, &image);
        return status ? fail(Error::Hardware, status) : true;
    }
    return fail(Error::Lease, readFailed_ ? ArmSmmu4KIoError : ArmSmmu4KBusy);
}

inline bool Owner::ufsUnchanged()
{
    using namespace nabu_usb::smmu;
    unsigned pages = 1u << (((result_.id1 >> 28) & 7) + 1);
    size_t offset = context_offset(pages, ufsBank_);
    bool same = read(kSmrBase + 4 * ufsSlot_) == ufsSmr_ &&
        read(kS2crBase + 4 * ufsSlot_) == ufsS2cr_;
    for (unsigned i = 0; i < 10; ++i) same = (read(offset + detail::UfsOffsets[i]) == ufsRegisters_[i]) && same;
    same = (read(kCbarBase + 4 * ufsBank_) == ufsCbar_) && same;
    same = (read(kCba2rBase + 4 * ufsBank_) == ufsCba2r_) && same;
    if (readFailed_) return fail(Error::Hardware, ArmSmmu4KIoError);
    return same ? true : fail(Error::Ufs, ArmSmmu4KStateMismatch);
}

inline bool Owner::selectionUnchanged()
{
    using namespace nabu_usb::smmu;
    if (read(kIdr0) != result_.id0 || read(kIdr1) != result_.id1 || read(kIdr2) != result_.id2 ||
        read(0) != result_.scr0 || read(kGfsr) != 0 ||
        read(bankOffset_) != selectedSctlr_ || read(bankOffset_ + 4) != selectedActlr_) {
        return fail(Error::Hardware, readFailed_ ? ArmSmmu4KIoError : ArmSmmu4KStateMismatch);
    }
    for (unsigned n = 0; n < StreamCount; ++n) {
        const auto &route = result_.lease.routes[n];
        if (read(kSmrBase + 4 * route.slot) != oldSmr_[n] ||
            read(kS2crBase + 4 * route.slot) != oldS2cr_[n]) {
            return fail(Error::Lease, readFailed_ ? ArmSmmu4KIoError : ArmSmmu4KStateMismatch);
        }
    }
    Info info{};
    if (!read_info([this](uint32_t at) { return read(at); }, &info, SmmuBytes) || readFailed_) {
        return fail(Error::Hardware, readFailed_ ? ArmSmmu4KIoError : ArmSmmu4KUnsupported);
    }
    for (unsigned slot = 0; slot < info.num_smr; ++slot) {
        uint32_t smr = read(kSmrBase + 4 * slot), s2cr = read(kS2crBase + 4 * slot);
        if (!(smr & kSmrValid)) continue;
        if ((s2cr & kS2crTypeMask) == 0 && (s2cr & kS2crCbndxMask) == result_.lease.bank) {
            return fail(Error::Lease, ArmSmmu4KBusy);
        }
        uint32_t mask = (smr >> 16) & 0x7fff;
        for (const auto &route : result_.lease.routes) {
            if (!((route.sid ^ smr) & ~mask & stream_id_mask(info))) return fail(Error::Lease, ArmSmmu4KOverlap);
        }
    }
    for (unsigned bank = 0; bank < info.num_cb; ++bank) {
        size_t offset = context_offset(info.global_pages, bank);
        if ((read(offset) & 1) && ((read(offset + 0x24) >> 16) == result_.lease.asid ||
            (read(offset + 0x2c) >> 16) == result_.lease.asid)) return fail(Error::Lease, ArmSmmu4KBusy);
    }
    if (readFailed_) return fail(Error::Hardware, ArmSmmu4KIoError);
    return ufsUnchanged();
}

inline bool Owner::faultRoutes()
{
    bool exact = true;
    for (unsigned n = 0; n < StreamCount; ++n) {
        size_t at = 0xc00 + 4 * result_.lease.routes[n].slot;
        if (!write(at, detail::Fault)) return false;
        result_.faultDirect[n] = result_.faultReadback[n] = read(at);
        if (result_.faultDirect[n] != detail::Fault) exact = false;
    }
    if (readFailed_) return fail(Error::Hardware, ArmSmmu4KIoError);
    if (exact) return true;
    for (unsigned n = 0; n < StreamCount; ++n) {
        const auto &route = result_.lease.routes[n];
        if (read(0x800 + 4 * route.slot) != oldSmr_[n] ||
            (result_.faultDirect[n] != detail::Fault && result_.faultDirect[n] != oldS2cr_[n])) {
            return fail(Error::Hardware, ArmSmmu4KStateMismatch);
        }
    }
    if (readFailed_) return fail(Error::Hardware, ArmSmmu4KIoError);
    /* Probe only still-invalid, exclusively leased slots. An ordinary SMMU
     * may read back BYPASS, so keep SMRs invalid and retain on that outcome. */
    for (unsigned n = 0; n < StreamCount; ++n) {
        size_t at = 0xc00 + 4 * result_.lease.routes[n].slot;
        if (!write(at, 1u << 16)) return false;
        result_.faultReadback[n] = read(at);
        if (readFailed_ || result_.faultReadback[n] != detail::Fault) {
            for (const auto &route : result_.lease.routes) (void)write(0xc00 + 4 * route.slot, detail::Fault);
            return fail(Error::Hardware, readFailed_ ? ArmSmmu4KIoError : ArmSmmu4KStateMismatch);
        }
    }
    result_.faultEncodingQuirk = true;
    return true;
}

inline bool Owner::activateLocked()
{
    int status = activation_.mastersStopped(activation_.cookie);
    if (status) return fail(Error::Hardware, status);
    if (!select() || !audit()) return false;
    result_.stage = Stage::Claim;
    status = activation_.claim(activation_.cookie, &result_.lease);
    if (status) return fail(Error::Lease, status);
    result_.leaseHeld = true;
    result_.state = State::Retained;
    result_.stage = Stage::FaultHandler;
    result_.faultHandlerAttempted = true;
    status = activation_.installFaults(activation_.cookie, &result_.lease, &io_);
    if (status) return fail(Error::FaultHandler, status);
    if (!selectionUnchanged()) return false;
    result_.stage = Stage::Actlr;
    result_.hardwareAttempted = true;
    if (!write(bankOffset_ + 4, 0)) return false;
    if (read(bankOffset_ + 4) != 0 || readFailed_) {
        return fail(Error::Hardware, readFailed_ ? ArmSmmu4KIoError : ArmSmmu4KStateMismatch);
    }
    result_.stage = Stage::FaultRoutes;
    if (!faultRoutes()) return false;
    status = ArmSmmu4KCheckFaultedStreams(&io_, result_.lease.routes, StreamCount,
        result_.lease.bank, ArmSmmu4KShareabilityFromTransaction, &result_.streams);
    if (status) return fail(Error::Hardware, status);
    result_.stage = Stage::Context;
    status = ArmSmmu4KProgramDisabledContext(&io_, result_.lease.bank, &context_,
        detail::PollBudget, &result_.program);
    if (status) return fail(Error::Hardware, status);
    result_.stage = Stage::Streams;
    status = ArmSmmu4KAttachStreams(&io_, &streams_, result_.lease.routes, StreamCount,
        result_.lease.bank, &context_, &result_.streams);
    if (status) return fail(Error::Hardware, status);
    if (!ufsUnchanged()) return false;
    result_.state = State::Active;
    result_.lastStatus = 0;
    return true;
}

inline bool Owner::activate(const Activation &activation)
{
    if (!enter()) return false;
    bool ok = false;
    if (result_.state != State::Prepared || result_.leaseHeld || result_.error != Error::None) {
        fail(Error::Busy, ArmSmmu4KBusy);
    } else {
        result_.stage = Stage::Dependencies;
        if (activation.physical != SmmuBase || activation.io.register_bytes != SmmuBytes ||
            !activation.io.read32 || !activation.io.read64 || !activation.io.write32 ||
            !activation.io.write64 || !activation.io.barrier || !activation.lock ||
            !activation.unlock || !activation.claim || !activation.mastersStopped || !activation.installFaults) {
            fail(Error::Dependency, ArmSmmu4KArgument);
        } else {
            activation_ = activation;
            configureIo();
            readFailed_ = false;
            int status = activation_.lock(activation_.cookie);
            if (status) fail(Error::Lease, status);
            else {
                ok = activateLocked();
                activation_.unlock(activation_.cookie);
            }
        }
    }
    leave();
    return ok;
}

inline bool Owner::memory(View &view)
{
    view = {};
    if (!enter()) return false;
    bool ok = result_.state == State::Active && result_.error == Error::None;
    if (ok) view = {arena_.cpu, uint32_t(IovaBase), ArenaBytes};
    leave();
    return ok;
}

inline bool Owner::publish(size_t offset, size_t bytes)
{
    if (!enter()) return false;
    bool ok = false;
    if (result_.state == State::Active && result_.error == Error::None &&
        bytes && offset <= ArenaBytes && bytes <= ArenaBytes - offset) {
        int status = platform_.publish(platform_.cookie, &arena_, offset, bytes);
        ok = status == 0;
        if (status) {
            fail(Error::Publish, status);
            if (result_.leaseHeld) result_.state = State::Retained;
        }
    }
    leave();
    return ok;
}

inline bool Owner::observeLocked()
{
    result_.stage = Stage::Observation;
    int status = ArmSmmu4KObserveStreams(&io_, &streams_, &context_, &result_.streams);
    result_.globalFault = result_.streams.global_fault;
    if (status) return fail(Error::Hardware, status);
    if (read(bankOffset_ + 4) != 0 || readFailed_) {
        return fail(Error::Hardware, readFailed_ ? ArmSmmu4KIoError : ArmSmmu4KStateMismatch);
    }
    return ufsUnchanged();
}

inline bool Owner::observe()
{
    if (!enter()) return false;
    bool ok = false;
    if (result_.state == State::Active) {
        readFailed_ = false;
        int status = activation_.lock(activation_.cookie);
        if (status) fail(Error::Lease, status);
        else {
            ok = observeLocked();
            activation_.unlock(activation_.cookie);
        }
        if (!ok) result_.state = State::Retained;
    }
    leave();
    return ok;
}

inline bool Owner::stopLocked()
{
    result_.stage = Stage::Stop;
    int status = activation_.mastersStopped(activation_.cookie);
    if (status) return fail(Error::Hardware, status);
    if ((!streams_.attached && !result_.stopFaulted) || streams_.poisoned) {
        return fail(Error::Hardware, ArmSmmu4KBusy);
    }
    /* Check foreign routes before any write. Context faults remain latched.
     * FaultStreams validates the exact owned routes and retains on failure. */
    using namespace nabu_usb::smmu;
    Info info{};
    bool supported = read_info([this](uint32_t at) { return read(at); }, &info, SmmuBytes);
    if (readFailed_) return fail(Error::Hardware, ArmSmmu4KIoError);
    if (!supported || info.idr0 != result_.id0 || info.idr1 != result_.id1 || info.idr2 != result_.id2) {
        return fail(Error::Hardware, ArmSmmu4KStateMismatch);
    }
    for (unsigned slot = 0; slot < info.num_smr; ++slot) {
        uint32_t smr = read(kSmrBase + 4 * slot), s2cr = read(kS2crBase + 4 * slot);
        if (!(smr & kSmrValid)) continue;
        bool owned = slot == result_.lease.routes[0].slot || slot == result_.lease.routes[1].slot;
        if (owned) continue;
        if ((s2cr & kS2crTypeMask) == 0 && (s2cr & kS2crCbndxMask) == result_.lease.bank) {
            return fail(Error::Lease, ArmSmmu4KBusy);
        }
        uint32_t mask = (smr >> 16) & 0x7fff;
        for (const auto &route : result_.lease.routes) {
            if (!((route.sid ^ smr) & ~mask & stream_id_mask(info))) return fail(Error::Lease, ArmSmmu4KOverlap);
        }
    }
    if (readFailed_) return fail(Error::Hardware, ArmSmmu4KIoError);
    if (!ufsUnchanged()) return false;
    if (result_.stopFaulted) {
        status = ArmSmmu4KCheckFaultedStreams(&io_, result_.lease.routes, StreamCount,
            result_.lease.bank, ArmSmmu4KShareabilityFromTransaction, &result_.streams);
    } else {
        status = ArmSmmu4KFaultStreams(&io_, &streams_, &result_.streams);
    }
    if (status) return fail(Error::Hardware, status);
    result_.stopFaulted = true;
    result_.lastStatus = 0;
    return true;
}

inline bool Owner::retainedStop()
{
    if (!enter()) return false;
    bool ok = false;
    if (result_.leaseHeld) {
        result_.state = State::Retained;
        readFailed_ = false;
        int status = activation_.lock(activation_.cookie);
        if (status) fail(Error::Lease, status);
        else {
            ok = stopLocked();
            activation_.unlock(activation_.cookie);
        }
    }
    leave();
    return ok;
}

inline bool Owner::releasePrepared()
{
    if (!enter()) return false;
    bool ok = !result_.leaseHeld && !result_.faultHandlerAttempted && !result_.hardwareAttempted;
    if (ok && arena_.cpu) {
        result_.stage = Stage::Release;
        releaseMemory();
    }
    leave();
    return ok;
}

inline bool Owner::retainFault(int status)
{
    if (!enter()) return false;
    if (result_.leaseHeld) {
        result_.stage = Stage::Observation;
        fail(Error::Hardware, status);
    }
    leave();
    return false;
}

inline bool RadioGate::confirmPasStop()
{
    if (__atomic_load_n(&authAttempted_, __ATOMIC_ACQUIRE)) return false;
    __atomic_store_n(&stopped_, 1, __ATOMIC_RELEASE);
    if (__atomic_load_n(&authAttempted_, __ATOMIC_ACQUIRE)) {
        __atomic_store_n(&stopped_, 0, __ATOMIC_RELEASE);
        return false;
    }
    return true;
}

inline void RadioGate::authAttempted()
{
    __atomic_store_n(&authAttempted_, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&stopped_, 0, __ATOMIC_RELEASE);
}

/* Portable normal entry used by the native adapter. The caller's successful
 * PAS shutdown is the physical stop evidence, confirmPasStop consumes that
 * phase before activate's real register/lease/IRQ checks. */
inline int activateAfterPasStop(Owner &owner, const Platform &platform,
    const Activation &activation, RadioGate &gate)
{
    if (owner.result().state == State::Empty && !owner.prepare(platform)) {
        return owner.result().lastStatus ? owner.result().lastStatus : RadioUnavailable;
    }
    if (owner.result().state != State::Prepared || owner.result().error != Error::None ||
        !gate.confirmPasStop()) return ArmSmmu4KBusy;
    if (!owner.activate(activation)) return owner.result().lastStatus ? owner.result().lastStatus : RadioUnavailable;
    if (!gate.stopped()) {
        owner.retainFault(ArmSmmu4KStateMismatch);
        return ArmSmmu4KStateMismatch;
    }
    return 0;
}

inline bool observeAfterFault(Owner &owner, const unsigned &faulted)
{
    if (__atomic_load_n(&faulted, __ATOMIC_ACQUIRE)) return owner.retainFault();
    bool observed = owner.observe();
    if (__atomic_load_n(&faulted, __ATOMIC_ACQUIRE)) return owner.retainFault();
    return observed;
}

inline int NativeLease::claim(const ArmSmmu4KIo &io, const Lease &requested)
{
    if (held || !io.read32 || !io.read64) return ArmSmmu4KBusy;
    using namespace nabu_usb::smmu;
    bool ioFailed = false;
    const auto read = [&](uint32_t at) {
        uint32_t value = 0;
        if (io.read32(io.cookie, at, &value)) ioFailed = true;
        return value;
    };
    Info info{};
    bool supported = read_info(read, &info, uint32_t(io.register_bytes));
    if (ioFailed) return ArmSmmu4KIoError;
    if (!supported || info.exids) return ArmSmmu4KUnsupported;
    if (!requested.bank || requested.bank >= info.num_cb || requested.bank < info.num_s2_cb ||
        requested.bank >= 80 || !requested.asid || requested.asid > 65535 ||
        requested.routes[0].slot == requested.routes[1].slot) return ArmSmmu4KArgument;
    for (unsigned n = 0; n < StreamCount; ++n) {
        const auto &route = requested.routes[n];
        if (route.sid != FirstSid + n || route.slot >= info.num_smr ||
            (read(kSmrBase + 4 * route.slot) & kSmrValid)) return ArmSmmu4KBusy;
    }
    if (read(context_offset(info.global_pages, requested.bank)) & 1) return ArmSmmu4KBusy;
    for (unsigned slot = 0; slot < info.num_smr; ++slot) {
        uint32_t smr = read(kSmrBase + 4 * slot), s2cr = read(kS2crBase + 4 * slot);
        if (!(smr & kSmrValid)) continue;
        if ((s2cr & kS2crTypeMask) == 0 && (s2cr & kS2crCbndxMask) == requested.bank) return ArmSmmu4KBusy;
        uint32_t mask = (smr >> 16) & 0x7fff;
        for (const auto &route : requested.routes) {
            if (!((route.sid ^ smr) & ~mask & stream_id_mask(info))) return ArmSmmu4KOverlap;
        }
    }
    for (unsigned bank = 0; bank < info.num_cb; ++bank) {
        size_t at = context_offset(info.global_pages, bank);
        if (!(read(uint32_t(at)) & 1)) continue;
        uint64_t lower = 0, upper = 0;
        if (io.read64(io.cookie, at + 0x20, &lower) || io.read64(io.cookie, at + 0x28, &upper)) return ArmSmmu4KIoError;
        if ((lower >> 48) == requested.asid || (upper >> 48) == requested.asid) return ArmSmmu4KBusy;
    }
    if (ioFailed) return ArmSmmu4KIoError;
    lease = requested;
    held = true;
    return 0;
}

inline void FaultLatch::record(const FaultRecord &record)
{
    unsigned expected = 0;
    if (!__atomic_compare_exchange_n(&writing_, &expected, 1, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
        __atomic_fetch_add(&dropped_, 1, __ATOMIC_SEQ_CST);
        return;
    }
    __atomic_fetch_add(&version_, 1, __ATOMIC_SEQ_CST);
    __atomic_store_n(&address_, record.address, __ATOMIC_SEQ_CST);
    __atomic_store_n(&status_, record.status, __ATOMIC_SEQ_CST);
    __atomic_store_n(&syndrome0_, record.syndrome0, __ATOMIC_SEQ_CST);
    __atomic_store_n(&syndrome1_, record.syndrome1, __ATOMIC_SEQ_CST);
    __atomic_store_n(&syndrome2_, record.syndrome2, __ATOMIC_SEQ_CST);
    __atomic_store_n(&sid_, record.sidField, __ATOMIC_SEQ_CST);
    __atomic_store_n(&bank_, record.bank, __ATOMIC_SEQ_CST);
    __atomic_store_n(&ackReadback_, record.ackReadback, __ATOMIC_SEQ_CST);
    __atomic_store_n(&ioStatus_, record.ioStatus, __ATOMIC_SEQ_CST);
    __atomic_fetch_add(&count_, 1, __ATOMIC_SEQ_CST);
    __atomic_fetch_add(&version_, 1, __ATOMIC_SEQ_CST);
    __atomic_store_n(&writing_, 0, __ATOMIC_SEQ_CST);
}

inline bool FaultLatch::read(FaultRecord &record) const
{
    for (unsigned attempt = 0; attempt < 3; ++attempt) {
        uint64_t before = __atomic_load_n(&version_, __ATOMIC_SEQ_CST);
        if (before & 1) continue;
        FaultRecord next;
        next.sequence = __atomic_load_n(&count_, __ATOMIC_SEQ_CST);
        next.dropped = __atomic_load_n(&dropped_, __ATOMIC_SEQ_CST);
        next.address = __atomic_load_n(&address_, __ATOMIC_SEQ_CST);
        next.status = __atomic_load_n(&status_, __ATOMIC_SEQ_CST);
        next.syndrome0 = __atomic_load_n(&syndrome0_, __ATOMIC_SEQ_CST);
        next.syndrome1 = __atomic_load_n(&syndrome1_, __ATOMIC_SEQ_CST);
        next.syndrome2 = __atomic_load_n(&syndrome2_, __ATOMIC_SEQ_CST);
        next.sidField = __atomic_load_n(&sid_, __ATOMIC_SEQ_CST);
        next.bank = __atomic_load_n(&bank_, __ATOMIC_SEQ_CST);
        next.ackReadback = __atomic_load_n(&ackReadback_, __ATOMIC_SEQ_CST);
        next.ioStatus = __atomic_load_n(&ioStatus_, __ATOMIC_SEQ_CST);
        if (before == __atomic_load_n(&version_, __ATOMIC_SEQ_CST) && next.sequence) {
            record = next;
            return true;
        }
    }
    return false;
}

inline void captureGlobalFault(void *cookie)
{
    auto &handler = *static_cast<FaultHandler *>(cookie);
    FaultRecord record;
    record.ioStatus = handler.io.read32(handler.io.cookie, 0x48, &record.status);
    if (!record.status && !record.ioStatus) return;
    if (!record.ioStatus) {
        record.ioStatus = handler.io.read32(handler.io.cookie, 0x50, &record.syndrome0);
        if (!record.ioStatus) record.ioStatus = handler.io.read32(handler.io.cookie, 0x54, &record.syndrome1);
        if (!record.ioStatus) record.ioStatus = handler.io.read32(handler.io.cookie, 0x58, &record.syndrome2);
        record.sidField = record.syndrome1 & 0xffff;
        int ack = handler.io.write32(handler.io.cookie, 0x48, record.status);
        int barrier = handler.io.barrier(handler.io.cookie);
        if (!record.ioStatus) record.ioStatus = ack ? ack : barrier;
        int readback = handler.io.read32(handler.io.cookie, 0x48, &record.ackReadback);
        if (!record.ioStatus) record.ioStatus = readback;
        if (!record.ioStatus && (record.ackReadback & record.status)) record.ioStatus = ArmSmmu4KStateMismatch;
    }
    handler.latch->record(record);
}

inline void captureContextFault(void *cookie)
{
    auto &handler = *static_cast<FaultHandler *>(cookie);
    FaultRecord record;
    record.bank = handler.bank;
    record.ioStatus = handler.io.read32(handler.io.cookie, handler.contextOffset + 0x58, &record.status);
    if (!(record.status & 0xc00001fe) && !record.ioStatus) return;
    __atomic_store_n(&handler.faulted, 1, __ATOMIC_RELEASE);
    if (!record.ioStatus) {
        record.ioStatus = handler.io.read32(handler.io.cookie, handler.contextOffset + 0x68, &record.syndrome0);
        if (!record.ioStatus) record.ioStatus = handler.io.read32(handler.io.cookie, handler.contextOffset + 0x6c, &record.syndrome1);
        if (!record.ioStatus) record.ioStatus = handler.io.read32(handler.io.cookie, 0x1400 + 4 * handler.bank, &record.syndrome2);
        if (!record.ioStatus) record.ioStatus = handler.io.read64(handler.io.cookie, handler.contextOffset + 0x60, &record.address);
        record.sidField = record.syndrome2 & 0xffff;
        int ack = handler.io.write32(handler.io.cookie, handler.contextOffset + 0x58, record.status);
        int barrier = handler.io.barrier(handler.io.cookie);
        if (!record.ioStatus) record.ioStatus = ack ? ack : barrier;
        int readback = handler.io.read32(handler.io.cookie, handler.contextOffset + 0x58, &record.ackReadback);
        if (!record.ioStatus) record.ioStatus = readback;
        if (!record.ioStatus && (record.ackReadback & record.status & 0xc00001fe)) record.ioStatus = ArmSmmu4KStateMismatch;
    }
    handler.latch->record(record);
}

inline int FaultIrqs::install(const IrqOps &ops, const ArmSmmu4KIo &io, const Lease &lease)
{
    if (attempted) return status ? status : ArmSmmu4KBusy;
    if (!ops.attach || !io.read32 || !io.read64 || !io.write32 || !io.barrier || lease.bank >= 80) return ArmSmmu4KArgument;
    uint32_t id1 = 0;
    int error = io.read32(io.cookie, 0x24, &id1);
    if (error) return error;
    if ((id1 >> 31) || lease.bank >= (id1 & 255)) return ArmSmmu4KUnsupported;
    size_t offset = nabu_usb::smmu::context_offset(1u << (((id1 >> 28) & 7) + 1), lease.bank);
    if (offset > io.register_bytes || io.register_bytes - offset < 4096) return ArmSmmu4KBadRange;
    const auto &spec = ContextFaultIrqs[lease.bank];
    if (spec.type != 0 || spec.flags != 4 || GlobalFaultIrq.type != 0 || GlobalFaultIrq.flags != 4) return ArmSmmu4KUnsupported;
    globalHandler.io = io;
    globalHandler.latch = &global;
    contextHandler.io = io;
    contextHandler.latch = &context;
    contextHandler.bank = lease.bank;
    contextHandler.contextOffset = offset;
    attempted = true;
    status = ops.attach(ops.cookie, GlobalFaultIrq.spi + 32, false, captureGlobalFault,
        &globalHandler, &globalReadback, &globalRouter);
    if (status) return status;
    if (globalReadback != 0xa003) return status = ArmSmmu4KStateMismatch;
    status = ops.attach(ops.cookie, spec.spi + 32, false, captureContextFault,
        &contextHandler, &contextReadback, &contextRouter);
    if (status) return status;
    if (contextReadback != 0xa003 || contextRouter != globalRouter) return status = ArmSmmu4KStateMismatch;
    return 0;
}

} // namespace NabuWifiDma
#endif // NABU_WIFI_RADIO or portable harness
#endif
