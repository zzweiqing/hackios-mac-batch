/* SPDX-License-Identifier: MIT */
#include "NabuAudio.h"

namespace NabuAudio {

const Qualification &sourceQualification()
{
#if XNU_NABU_AUDIO
    static const Qualification result = {
        1,
        State::DependenciesMissing,
        AdspFirmware | SharedPowerOwner | AdspTransport | AudioDmaOwner |
            SpeakerProtection | SpeakerBus | TargetAudioAbi | CurrentKernelBindings,
    };
#else
    static const Qualification result = {1, State::Disabled, 0};
#endif
    return result;
}

} // namespace NabuAudio
