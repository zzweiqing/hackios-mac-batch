// Temporary CPU-only scanout/progress stubs for the first nabu observation.
// They are NOT the final owner protocol: the text console can still overwrite
// the copied frame.  The boot args keep the text console visible so the
// observation log can be photographed; replace this file with the owner
// handoff before claiming a stable SpringBoard frame.
#include <stdint.h>

extern "C" int boot_progress_prepare_scanout(void) { return 1; }
extern "C" void boot_progress_cancel_scanout(void) {}
extern "C" void boot_progress_stage(const char *) {}
extern "C" int boot_progress_pulse_anchor(uintptr_t, uint64_t, unsigned, unsigned, unsigned) {
    return 0;
}