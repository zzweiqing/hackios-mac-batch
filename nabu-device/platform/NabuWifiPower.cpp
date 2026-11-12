/* SPDX-License-Identifier: MIT */
/* Original implementation of the nabu ARC/TCS/QMP wire protocols, checked
 * against NativeAdrenoA6xxPower.cpp and the fixed ios-flame wland.c. */
#include "NabuWifiPower.h"
#include <string.h>

#ifndef NABU_WIFI_MPSS_HOST_TEST
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOLib.h>
#include <kern/clock.h>
#include <pexpert/pexpert.h>
extern "C" uint64_t gPhysBase, gPhysSize;
#endif

namespace NabuWifiPower {
namespace {
constexpr uint32_t Bit(unsigned bit) { return uint32_t(1) << bit; }
constexpr uint32_t CommandDbBytes = 0x20000;
constexpr uint32_t QmpUp = 0xffff;

struct Operation {
    uint32_t *state;
    bool acquired;
    explicit Operation(uint32_t *value) : state(value), acquired(false)
    {
        uint32_t expected = 0;
        acquired = __atomic_compare_exchange_n(state, &expected, 1, false,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
    }
    ~Operation()
    {
        if (acquired) {
            __atomic_store_n(state, 0, __ATOMIC_RELEASE);
        }
    }
};
}

void Power::log()
{
    if (io_.log) {
        io_.log(io_.ctx, &report_);
    }
}

int Power::fail(Error error, int status)
{
    report_.error = error;
    report_.status = status ? status : -1;
    log();
    return report_.status;
}

int Power::read(Domain domain, uint32_t offset, uint32_t *value)
{
    report_.domain = domain;
    report_.offset = offset;
    int status = io_.read32(io_.ctx, domain, offset, value);
    if (status) {
        return fail(Error::Io, status);
    }
    report_.value = *value;
    return 0;
}

int Power::write(Domain domain, uint32_t offset, uint32_t value)
{
    report_.domain = domain;
    report_.offset = offset;
    report_.value = value;
    int status = io_.write32(io_.ctx, domain, offset, value);
    return status ? fail(Error::Io, status) : 0;
}

int Power::poll(Domain domain, uint32_t offset, uint32_t mask,
    uint32_t expected, uint64_t timeout)
{
    report_.expected = expected;
    report_.mask = mask;
    uint64_t start = 0;
    int status = io_.nowUs(io_.ctx, &start);
    if (status) {
        return fail(Error::Clock, status);
    }
    uint64_t previous = start;
    for (uint64_t attempt = 0; attempt <= timeout / 10; ++attempt) {
        uint32_t value = 0;
        status = read(domain, offset, &value);
        if (status || (value & mask) == expected) {
            return status;
        }
        uint64_t now = 0;
        status = io_.nowUs(io_.ctx, &now);
        if (status || now < previous) {
            return fail(Error::Clock, status);
        }
        previous = now;
        if (now - start >= timeout) {
            break;
        }
        status = io_.waitUs(io_.ctx, 10);
        if (status) {
            return fail(Error::Io, status);
        }
    }
    return fail(Error::Timeout);
}

int Power::findResources()
{
    report_.stage = Stage::CommandDb;
    uint32_t pointer = 0, magic = 0, version = 0;
    int status = read(Domain::CommandDbInfo, 0, &pointer);
    if (status) return status;
    if (pointer != 0x85f20000) return fail(Error::Resource);
    status = read(Domain::CommandDb, 0, &version);
    if (status) return status;
    status = read(Domain::CommandDb, 4, &magic);
    if (status) return status;
    if (!version || magic != 0x0c0330db) return fail(Error::Resource);

    const char *const names[] = {"cx.lvl", "mss.lvl", "xo.lvl"};
    Resource *const resources[] = {&cx_, &mss_, &xo_};
    uint32_t seen = 0;
    for (unsigned slave = 0; slave < 8; ++slave) {
        uint32_t header0 = 0, header1 = 0;
        status = read(Domain::CommandDb, 8 + slave * 16, &header0);
        if (status) return status;
        status = read(Domain::CommandDb, 12 + slave * 16, &header1);
        if (status) return status;
        const uint32_t slaveId = header0 & 0xffff;
        if (!slaveId) break;
        const uint32_t records = 144 + (header0 >> 16);
        const uint32_t auxiliary = 144 + (header1 & 0xffff);
        const uint32_t count = header1 >> 16;
        if (records > CommandDbBytes || count > 4096 ||
            count * 24 > CommandDbBytes - records) return fail(Error::Resource);
        for (uint32_t entry = 0; entry < count; ++entry) {
            uint32_t record[6]{};
            for (unsigned word = 0; word < 6; ++word) {
                status = read(Domain::CommandDb, records + entry * 24 + word * 4,
                    &record[word]);
                if (status) return status;
            }
            char name[9]{};
            for (unsigned byte = 0; byte < 8; ++byte) {
                name[byte] = char(record[byte / 4] >> (byte % 4 * 8));
            }
            for (unsigned resource = 0; resource < 3; ++resource) {
                if (strcmp(name, names[resource])) continue;
                const uint32_t bytes = record[5] & 0xffff;
                const uint32_t offset = auxiliary + (record[5] >> 16);
                if ((seen & Bit(resource)) || slaveId != 3 || !record[4] ||
                    (record[4] & 3) || ((record[4] >> 16) & 7) != 3 ||
                    (resource < 2 && !bytes) || (bytes & 1) || bytes > 512 ||
                    (offset & 1) || offset > CommandDbBytes || bytes > CommandDbBytes - offset) {
                    return fail(Error::Resource);
                }
                Resource &destination = *resources[resource];
                destination.address = record[4];
                destination.count = bytes / 2;
                uint16_t previous = 0;
                bool terminated = false;
                for (unsigned level = 0; level < destination.count; ++level) {
                    uint32_t word = 0;
                    status = read(Domain::CommandDb, (offset + level * 2) & ~3u, &word);
                    if (status) return status;
                    const uint16_t value = uint16_t(word >> ((offset + level * 2) % 4 * 8));
                    if ((level == 0 && value) || (value && (terminated || value < previous))) {
                        return fail(Error::Resource);
                    }
                    if (level && !value) terminated = true;
                    destination.levels[level] = value;
                    if (value) previous = value;
                }
                seen |= Bit(resource);
                report_.resourceAddress = destination.address;
                log();
            }
        }
    }
    return seen == 7 ? 0 : fail(Error::Resource);
}

int Power::beginBeforeGpu(const Io &io, uint64_t managedBase, uint64_t managedBytes)
{
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&attempted_, &expected, 1, false,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return -1;
    io_ = io;
    report_.managedBase = managedBase;
    report_.managedBytes = managedBytes;
    if (!io.read32 || !io.write32 || !io.nowUs || !io.waitUs) {
        return fail(Error::MissingIo);
    }
    if (!NabuWifiMpss::managedWindowValid(managedBase, managedBytes)) {
        return fail(Error::Resource);
    }
    int status = findResources();
    if (!status) begun_ = true;
    return status;
}

int Power::submitVote(uint32_t address, uint32_t value)
{
    report_.stage = Stage::TcsPrepare;
    uint32_t configuration = 0;
    int status = read(Domain::Rpmh, 0x0c, &configuration);
    if (status) return status;
    if (((configuration >> 12) & 0x3f) < 2 || (configuration >> 27) < 1) {
        return fail(Error::Resource);
    }
    /* An occupied slot is evidence of another APPS owner even if the other
     * slot is free. Do not program either slot in that case. */
    for (unsigned slot = 0; slot < 2; ++slot) {
        uint32_t enabled = 0;
        status = read(Domain::Rpmh, 0xd00 + slot * 672 + 0x1c, &enabled);
        if (status) return status;
        if (enabled) return fail(Error::Busy);
    }
    constexpr unsigned tcs = 0;
    const uint32_t base = 0xd00 + tcs * 672;
    uint32_t control = 0;
    status = read(Domain::Rpmh, base + 0x14, &control);
    if (status) return status;
    /* From the first control write a partially changed channel remains ours.
     * Errors leave it untouched for diagnosis and prevent the GPU handoff. */
    report_.pending = true;
    const uint32_t controls[] = {
        control & ~Bit(24), control & ~(Bit(24) | Bit(16)), Bit(16)
    };
    for (uint32_t next : controls) {
        status = write(Domain::Rpmh, base + 0x14, next);
        if (status) return status;
        status = poll(Domain::Rpmh, base + 0x14, UINT32_MAX, next, 1000);
        if (status) return status;
    }
    status = write(Domain::Rpmh, 0xd08, Bit(tcs));
    if (status) return status;
    status = write(Domain::Rpmh, base + 0x30, 0x10108);
    if (status) return status;
    status = write(Domain::Rpmh, base + 0x34, address);
    if (status) return status;
    status = write(Domain::Rpmh, base + 0x38, value);
    if (status) return status;
    status = write(Domain::Rpmh, base + 0x10, 1);
    if (status) return status;
    status = write(Domain::Rpmh, base + 0x1c, 1);
    if (status) return status;
    report_.stage = Stage::TcsSubmit;
    log();
    status = write(Domain::Rpmh, base + 0x14, Bit(16) | Bit(24));
    if (status) return status;
    status = poll(Domain::Rpmh, 0xd04, Bit(tcs), Bit(tcs), 100000);
    if (status) return status;
    status = poll(Domain::Rpmh, base + 0x3c, Bit(8) | Bit(16), Bit(8) | Bit(16), 1000);
    if (status) return status;
    report_.stage = Stage::TcsComplete;
    status = write(Domain::Rpmh, base + 0x1c, 0);
    if (status) return status;
    status = write(Domain::Rpmh, 0xd08, Bit(tcs));
    if (status) return status;
    report_.pending = false;
    log();
    return 0;
}

int Power::vote(const char *name, uint32_t level)
{
    Operation operation(&operation_);
    if (!operation.acquired) return -1;
    if (report_.error != Error::None) return report_.status;
    if (!begun_ || released_ || !name || level != 385) {
        return fail(Error::Sequence);
    }
    Resource *resource = nullptr;
    if (!strcmp(name, "cx.lvl")) {
        report_.stage = Stage::VoteCx;
        resource = &cx_;
    } else if (!strcmp(name, "mss.lvl")) {
        report_.stage = Stage::VoteMss;
        resource = &mss_;
    } else {
        return fail(Error::Resource);
    }
    if (resource->held) return fail(Error::Sequence);
    unsigned index = 1;
    while (index < resource->count && resource->levels[index] &&
        resource->levels[index] < level) ++index;
    if (index >= resource->count || !resource->levels[index]) return fail(Error::Level);
    report_.resourceAddress = resource->address;
    report_.requestedLevel = level;
    report_.levelIndex = index;
    log();
    int status = submitVote(resource->address, index);
    if (!status) {
        resource->heldIndex = index;
        resource->held = true;
    }
    return status;
}

int Power::enableXo()
{
    Operation operation(&operation_);
    if (!operation.acquired) return -1;
    if (report_.error != Error::None) return report_.status;
    if (!begun_ || released_ ||
        !cx_.held || !mss_.held || xoEnabled_) return fail(Error::Sequence);
    report_.stage = Stage::EnableXo;
    report_.resourceAddress = xo_.address;
    report_.requestedLevel = 0;
    report_.levelIndex = 3;
    log();
    int status = submitVote(xo_.address, 3);
    if (!status) {
        xoEnabled_ = true;
        xo_.held = true;
        xo_.heldIndex = 3;
    }
    return status;
}

int Power::ring()
{
    return write(Domain::Doorbell, 0, 1);
}

int Power::openQmp()
{
    report_.stage = Stage::QmpOpen;
    uint32_t magic = 0, version = 0;
    int status = read(Domain::Qmp, 0, &magic);
    if (status) return status;
    status = read(Domain::Qmp, 4, &version);
    if (status) return status;
    if (magic != 0x4d41494c || version != 1) return fail(Error::Resource);
    status = read(Domain::Qmp, 52, &mailboxBytes_);
    if (status) return status;
    status = read(Domain::Qmp, 56, &mailboxOffset_);
    if (status) return status;
    if (mailboxOffset_ < 64 || (mailboxOffset_ & 3) || mailboxBytes_ < 64 ||
        mailboxOffset_ > 0x400 || mailboxBytes_ > 0x400 - mailboxOffset_) {
        return fail(Error::Resource);
    }
    uint32_t states[10]{};
    for (unsigned index = 0; index < 10; ++index) {
        status = read(Domain::Qmp, 12 + 4 * index, &states[index]);
        if (status) return status;
    }
    if (states[0] == QmpUp && states[1] == QmpUp && states[2] == QmpUp &&
        states[3] == QmpUp && states[6] == QmpUp && states[7] == QmpUp &&
        states[8] == QmpUp && states[9] == QmpUp) {
        linkUp_ = true;
        return 0;
    }
    report_.pending = true;
    status = write(Domain::Qmp, 16, states[0]);
    if (status) return status;
    status = write(Domain::Qmp, 36, QmpUp);
    if (status) return status;
    status = ring();
    if (status) return status;
    status = poll(Domain::Qmp, 40, UINT32_MAX, QmpUp, 1000000);
    if (status) return status;
    status = write(Domain::Qmp, 44, QmpUp);
    if (status) return status;
    status = ring();
    if (status) return status;
    status = poll(Domain::Qmp, 20, UINT32_MAX, QmpUp, 1000000);
    if (status) return status;
    status = write(Domain::Qmp, 24, QmpUp);
    if (status) return status;
    status = ring();
    if (status) return status;
    status = poll(Domain::Qmp, 48, UINT32_MAX, QmpUp, 1000000);
    if (status) return status;
    linkUp_ = true;
    report_.pending = false;
    return 0;
}

int Power::setModemLoadState()
{
    Operation operation(&operation_);
    if (!operation.acquired) return -1;
    if (report_.error != Error::None) return report_.status;
    if (!begun_ || released_ ||
        !xoEnabled_ || loadStateOn_) return fail(Error::Sequence);
    int status = openQmp();
    if (status) return status;
    const char message[] = "{class: image, res: load_state, name: modem, val: on}";
    const uint32_t bytes = (sizeof(message) + 3) & ~uint32_t(3);
    if (!linkUp_ || bytes + 4 > mailboxBytes_) return fail(Error::Resource);
    status = poll(Domain::Qmp, mailboxOffset_, UINT32_MAX, 0, 100000);
    if (status) return status;
    report_.stage = Stage::QmpSubmit;
    report_.pending = true;
    for (uint32_t offset = 0; offset < bytes; offset += 4) {
        uint32_t value = 0;
        for (unsigned byte = 0; byte < 4 && offset + byte < sizeof(message); ++byte) {
            value |= uint32_t(uint8_t(message[offset + byte])) << (byte * 8);
        }
        status = write(Domain::Qmp, mailboxOffset_ + 4 + offset, value);
        if (status) return status;
    }
    status = write(Domain::Qmp, mailboxOffset_, bytes);
    if (status) return status;
    log();
    status = ring();
    if (status) return status;
    status = poll(Domain::Qmp, mailboxOffset_, UINT32_MAX, 0, 1000000);
    if (status) return status;
    report_.stage = Stage::QmpComplete;
    report_.pending = false;
    loadStateOn_ = true;
    log();
    return 0;
}

bool Power::completeBeforeGpu()
{
    Operation operation(&operation_);
    if (!operation.acquired || !begun_ || released_ || report_.pending ||
        report_.error != Error::None || !loadStateOn_) return false;
    released_ = true;
    report_.stage = Stage::Released;
    log();
    return true;
}

uint32_t Power::mergeArcVote(uint32_t address, uint32_t value) const
{
    const Resource *const resources[] = {&cx_, &mss_, &xo_};
    for (const Resource *resource : resources) {
        if (resource->held && resource->address == address && value < resource->heldIndex) {
            return resource->heldIndex;
        }
    }
    return value;
}

#ifndef NABU_WIFI_MPSS_HOST_TEST
namespace {
struct NativeOwner {
    Power power;
    IOMemoryMap *maps[5]{};
    uint32_t claim = 0;
};
NativeOwner owner;
const uint64_t physical[] = {0x0c3f000c, 0x85f20000, 0x18220000, 0x0c300000, 0x17c0000c};
const size_t extent[] = {8, 0x20000, 0x3100, 0x1000, 4};

int nativeRead(void *, Domain domain, uint32_t offset, uint32_t *value)
{
    const unsigned index = unsigned(domain);
    if (index >= 5 || !owner.maps[index] || !value || (offset & 3) ||
        offset > extent[index] - 4) return int(kIOReturnBadArgument);
    *value = *reinterpret_cast<volatile uint32_t *>(
        owner.maps[index]->getVirtualAddress() + offset);
    __asm__ volatile("dsb ld" ::: "memory");
    return 0;
}

int nativeWrite(void *, Domain domain, uint32_t offset, uint32_t value)
{
    const unsigned index = unsigned(domain);
    if (index < 2 || index >= 5 || !owner.maps[index] || (offset & 3) ||
        offset > extent[index] - 4) return int(kIOReturnBadArgument);
    *reinterpret_cast<volatile uint32_t *>(owner.maps[index]->getVirtualAddress() + offset) = value;
    __asm__ volatile("dsb sy" ::: "memory");
    return 0;
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
    IODelay(microseconds);
    return 0;
}

void nativeLog(void *, const Report *report)
{
    IOLog("NabuWifiPower: stage=%u error=%u status=%d domain=%u offset=%x "
        "value=%x expected=%x mask=%x resource=%x level=%u index=%u pending=%u managed_base=%llx managed_bytes=%llx\n",
        unsigned(report->stage), unsigned(report->error), report->status,
        unsigned(report->domain), report->offset, report->value, report->expected,
        report->mask, report->resourceAddress, report->requestedLevel,
        report->levelIndex, report->pending,
        (unsigned long long)report->managedBase, (unsigned long long)report->managedBytes);
}
}

int beginBeforeGpu()
{
    uint32_t expected = 0;
    if (!__atomic_compare_exchange_n(&owner.claim, &expected, 1, false,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return int(kIOReturnBusy);
    unsigned mode = 0, gpu = 0;
    if (!PE_parse_boot_argn("nabu-wifi", &mode, sizeof(mode)) || mode != 2 ||
        !PE_parse_boot_argn("nabu-gpu", &gpu, sizeof(gpu)) || gpu != 0) {
        IOLog("NabuWifiPower: cold owner rejected wifi=%u gpu=%u\n", mode, gpu);
        return int(kIOReturnUnsupported);
    }
    const uint64_t managedBase = gPhysBase, managedBytes = gPhysSize;
    const bool valid = NabuWifiMpss::managedWindowValid(managedBase, managedBytes);
    IOLog("NabuWifiPower: managed base=%llx bytes=%llx valid=%u\n",
        (unsigned long long)managedBase, (unsigned long long)managedBytes, valid);
    if (!valid) {
        return int(kIOReturnUnsupported);
    }
    for (unsigned index = 0; index < 5; ++index) {
        IODeviceMemory *memory = IODeviceMemory::withRange(physical[index], extent[index]);
        if (!memory) {
            IOLog("NabuWifiPower: descriptor failed domain=%u physical=%llx bytes=%lu\n",
                index, (unsigned long long)physical[index], (unsigned long)extent[index]);
            return int(kIOReturnNoMemory);
        }
        owner.maps[index] = memory->map(kIOMapAnywhere | kIOMapInhibitCache);
        memory->release();
        if (!owner.maps[index] || !owner.maps[index]->getVirtualAddress() ||
            owner.maps[index]->getLength() != extent[index]) {
            IOLog("NabuWifiPower: mapping failed domain=%u physical=%llx bytes=%lu\n",
                index, (unsigned long long)physical[index], (unsigned long)extent[index]);
            return int(kIOReturnNoMemory);
        }
    }
    const Io io{nullptr, nativeRead, nativeWrite, nativeNow, nativeWait, nativeLog};
    return owner.power.beginBeforeGpu(io, managedBase, managedBytes);
}

int vote(void *, const char *name, uint32_t level) { return owner.power.vote(name, level); }
int enableXo(void *) { return owner.power.enableXo(); }
int setModemLoadState(void *) { return owner.power.setModemLoadState(); }
bool completeBeforeGpu() { return owner.power.completeBeforeGpu(); }
uint32_t mergeArcVote(uint32_t address, uint32_t value)
{
    return owner.power.mergeArcVote(address, value);
}
#endif
} // namespace NabuWifiPower
