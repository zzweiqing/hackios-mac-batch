/* SPDX-License-Identifier: MIT */
#ifndef NABU_WIFI_PAS_H
#define NABU_WIFI_PAS_H
#include "../gpu/a640/NabuScmCall.h"

/* Seven SCM arguments use x2..x4 directly, with arguments 3..6 in an owned
 * little-endian page addressed by x5. Preserve the original extended pointer
 * on every interrupted continuation and busy return. Reuse the production
 * bounded SCM executor, including Qualcomm's x6 continuation quirk. */
namespace NabuWifiPas {
struct ExtendedCall {
    const NabuScmIo *io;
    uint64_t physical;
    static void invoke(void *cookie, NabuScmRegisters *regs)
    {
        ExtendedCall &call = *static_cast<ExtendedCall *>(cookie);
        regs->x[5] = call.physical;
        call.io->invoke(call.io->cookie, regs);
    }
    static int now(void *cookie, uint64_t *value)
    {
        ExtendedCall &call = *static_cast<ExtendedCall *>(cookie);
        return call.io->now_us(call.io->cookie, value);
    }
    static int wait(void *cookie, unsigned microseconds)
    {
        ExtendedCall &call = *static_cast<ExtendedCall *>(cookie);
        return call.io->wait_us(call.io->cookie, microseconds);
    }
};
inline NabuScmReply assign(const NabuScmIo &io, uint32_t function,
    uint64_t memoryInfo, uint64_t sourceVmids, uint64_t extended)
{
    if (!io.invoke || !io.now_us || !io.wait_us || !extended) {
        return NabuScmReply{};
    }
    ExtendedCall call{&io, extended};
    const NabuScmIo wrapper{&call, ExtendedCall::invoke, ExtendedCall::now, ExtendedCall::wait};
    return nabuScmCall(wrapper, function, 0x1117, memoryInfo, 16, sourceVmids);
}
} // namespace NabuWifiPas
#endif
