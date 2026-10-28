// SPDX-License-Identifier: BSD-2-Clause-Patent
// Bounded, opt-in snapshots of existing software state; no registry or MMIO reads.
#include <IOKit/IOLib.h>
#include <kern/thread.h>
#include <pexpert/pexpert.h>

extern "C" {
extern volatile unsigned nabu_graphics_worker_stage;
extern volatile int native_mobile_graphics_load_status;
extern volatile uint32_t native_legacy_stage, native_legacy_surface_found;
extern volatile uint32_t native_legacy_surface_class_match;
extern volatile int native_legacy_meta_status, native_legacy_surface_status;
extern volatile uint32_t native_legacy_init_result, native_legacy_probe_match, native_legacy_start_result;
extern volatile int native_legacy_console_status;
extern volatile uint32_t native_legacy_console_width, native_legacy_console_height;
extern volatile uint32_t native_legacy_console_stride, native_legacy_console_rotation;
extern volatile uint64_t native_legacy_video_base, native_legacy_video_bytes;
extern volatile uint64_t native_legacy_gop_virtual, native_legacy_gop_physical, native_legacy_gop_bytes;
extern volatile uint32_t native_legacy_registration_calls, native_legacy_dt_attached;
extern volatile uint32_t native_legacy_client_calls;
extern volatile int native_legacy_client_pid, native_legacy_client_status;
extern volatile uint32_t native_legacy_swap_validation_calls, native_legacy_swap_validation_result;
extern volatile uint32_t native_legacy_swap_validation_reason;
extern volatile uint32_t native_legacy_transfer_calls, native_legacy_frame_count;
extern volatile int native_legacy_transfer_status;
extern volatile uint64_t native_legacy_transfer_bytes;
extern volatile uint32_t native_legacy_retirement_calls, native_legacy_retired_frames;
extern volatile uint32_t native_legacy_retired_generation, native_legacy_presented_generation;
extern volatile uint64_t native_legacy_retired_current, native_legacy_retired_pending;

#if defined(NABU_LEGACY_CPU_PRESENT)
extern volatile uint32_t nabu_legacy_cpu_present_abi, nabu_legacy_cpu_first_request_valid;
extern volatile uint64_t nabu_legacy_cpu_copied_frames, nabu_legacy_cpu_blank_frames;
extern volatile uint32_t nabu_legacy_cpu_console_owned, nabu_legacy_cpu_console_status;
extern volatile uint32_t nabu_keybag_notification_stage;
extern volatile int nabu_keybag_notification_status;
extern volatile uint32_t nabu_keybag_notification_subscriptions, nabu_keybag_notification_failures;
extern volatile uint32_t nabu_keybag_notification_refused_opens;
unsigned native_legacy_state_words(char *out, unsigned cap);
#endif

static void
nabu_graphics_status_worker(void *parameter, wait_result_t waitResult)
{
    (void)parameter;
    (void)waitResult;
    const unsigned delays[] = {2000, 3000, 5000, 10000, 10000, 30000,
                               60000, 120000, 180000, 180000};
    unsigned slept = 0, sample = 0;
    for (unsigned delay : delays) {
        IOSleep(delay);
        slept += delay;
        ++sample;
        // Independently sampled counters, not an atomic snapshot or uptime proof.
        // A transfer attempt can fail; retain later copy/completion observations.
        IOLog("NABU DISPLAY sample=%u sleep-ms=%u worker=%u family=%d legacy=%u meta=%d\n",
            sample, slept, nabu_graphics_worker_stage, native_mobile_graphics_load_status,
            native_legacy_stage, native_legacy_meta_status);
        IOLog("NABU DISPLAY console=%d %ux%u stride=%u rotate=%u init=%u\n",
            native_legacy_console_status, native_legacy_console_width, native_legacy_console_height,
            native_legacy_console_stride, native_legacy_console_rotation, native_legacy_init_result);
        IOLog("NABU DISPLAY surface=%d found=%u class=%u probe=%u start=%u registered=%u attached=%u\n",
            native_legacy_surface_status, native_legacy_surface_found, native_legacy_surface_class_match,
            native_legacy_probe_match, native_legacy_start_result,
            native_legacy_registration_calls, native_legacy_dt_attached);
        IOLog("NABU DISPLAY gop-pa=0x%llx gop-va=0x%llx gop-bytes=%llu video-pa=0x%llx video-bytes=%llu\n",
            (unsigned long long)native_legacy_gop_physical, (unsigned long long)native_legacy_gop_virtual,
            (unsigned long long)native_legacy_gop_bytes, (unsigned long long)native_legacy_video_base,
            (unsigned long long)native_legacy_video_bytes);
        IOLog("NABU DISPLAY client-calls=%u pid=%d status=0x%x validation-calls=%u valid=%u reason=%u\n",
            native_legacy_client_calls, native_legacy_client_pid, (unsigned)native_legacy_client_status,
            native_legacy_swap_validation_calls, native_legacy_swap_validation_result,
            native_legacy_swap_validation_reason);
        IOLog("NABU DISPLAY transfer-calls=%u status=0x%x bytes=%llu legacy-frames=%u\n",
            native_legacy_transfer_calls, (unsigned)native_legacy_transfer_status,
            (unsigned long long)native_legacy_transfer_bytes, native_legacy_frame_count);
        IOLog("NABU DISPLAY retirement-calls=%u retired-frames=%u generation=%u/%u current=0x%llx pending=0x%llx\n",
            native_legacy_retirement_calls, native_legacy_retired_frames,
            native_legacy_retired_generation, native_legacy_presented_generation,
            (unsigned long long)native_legacy_retired_current, (unsigned long long)native_legacy_retired_pending);
#if defined(NABU_LEGACY_CPU_PRESENT)
        IOLog("NABU DISPLAY cpu-abi=%u first-valid=%u copied=%llu blank=%llu console-owned=%u console-status=0x%x\n",
            nabu_legacy_cpu_present_abi, nabu_legacy_cpu_first_request_valid,
            (unsigned long long)nabu_legacy_cpu_copied_frames, (unsigned long long)nabu_legacy_cpu_blank_frames,
            nabu_legacy_cpu_console_owned, nabu_legacy_cpu_console_status);
        IOLog("NABU DISPLAY notify-stage=%u status=0x%x subscriptions=%u failures=%u refused-opens=%u\n",
            nabu_keybag_notification_stage, (unsigned)nabu_keybag_notification_status,
            nabu_keybag_notification_subscriptions, nabu_keybag_notification_failures,
            nabu_keybag_notification_refused_opens);
        char words[192];
        if (native_legacy_state_words(words, sizeof(words))) IOLog("NABU DISPLAY state %s\n", words);
#endif
    }
    thread_terminate(current_thread());
}

void
native_legacy_status_start(void)
{
    unsigned enabled = 0;
    if (!PE_parse_boot_argn("nabu-display-status", &enabled, sizeof(enabled)) || enabled != 1) return;
    thread_t worker = THREAD_NULL;
    kern_return_t result = kernel_thread_start(nabu_graphics_status_worker, nullptr, &worker);
    if (result == KERN_SUCCESS) thread_deallocate(worker);
    else IOLog("NABU DISPLAY status worker creation failed=%d\n", result);
}
}
