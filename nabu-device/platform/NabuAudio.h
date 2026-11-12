/* SPDX-License-Identifier: MIT */
#ifndef NABU_AUDIO_H
#define NABU_AUDIO_H

#include <stdint.h>

#ifndef XNU_NABU_AUDIO
#define XNU_NABU_AUDIO 0
#endif
#if XNU_NABU_AUDIO != 0 && XNU_NABU_AUDIO != 1
#error XNU_NABU_AUDIO_must_be_zero_or_one
#endif

namespace NabuAudio {

enum class State : uint32_t { Disabled, DependenciesMissing };

enum Missing : uint32_t {
    AdspFirmware = 1u << 0,
    SharedPowerOwner = 1u << 1,
    AdspTransport = 1u << 2,
    AudioDmaOwner = 1u << 3,
    SpeakerProtection = 1u << 4,
    SpeakerBus = 1u << 5,
    TargetAudioAbi = 1u << 6,
    CurrentKernelBindings = 1u << 7,
};

struct Qualification {
    uint32_t version;
    State state;
    uint32_t missing;
};

static_assert(sizeof(Qualification) == 12, "NabuAudio qualification layout");

/* This source-only integration gate has no hardware side effects. An enabled
 * build reports the unresolved owners and target bindings. It cannot authorize
 * a PAS request, an amplifier transaction or publication of a system route. */
const Qualification &sourceQualification();

} // namespace NabuAudio
#endif
