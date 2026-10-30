"""Opt-in boot transport for the signed ABI1 probe; no Apple job replacement."""

RAM_ANCHOR = 'extern "C" int native_ram_block_gpu_addon(const uint8_t **data,uint64_t *bytes) {\n'
RAM_MARKER = '/* NABU_GPU_USERPROBE_INLINE_V1 */'
DATA_MARKER = '\t/* NABU_GPU_USERPROBE_JOB_V1 */\n'
DATA_ANCHOR = 'native_gpu_addon_prepare(proc_t p, user_addr_t scratch)\n{\n'
PARENTS_BEFORE = '\tfor (size_t i = sizeof("/private/var/ngpu/") - 1; parent[i]; ++i) {\n'
PARENTS_AFTER = ('\t/* NABU_GPU_USERPROBE_PARENTS_V1: create ngpu before its children. */\n'
                 '\tfor (size_t i = sizeof("/private/var/") - 1; parent[i]; ++i) {\n')
RAM_HELPER = r'''/* NABU_GPU_USERPROBE_INLINE_V1 */
#include "NabuGpuUserprobeAddon.h"
static OSData *nabu_gpu_userprobe_retained;
static int nabu_gpu_userprobe_inline(const uint8_t **data, uint64_t *bytes)
{
  if (!nabu_gpu_userprobe_retained) {
    IORegistryEntry *chosen = IORegistryEntry::fromPath("/chosen", gIODTPlane);
    if (!chosen) return 0;
    OSData *blob = OSDynamicCast(OSData, chosen->getProperty("nabu-gpu-userprobe-addon"));
    OSData *identity = OSDynamicCast(OSData, chosen->getProperty("nabu-gpu-userprobe-sha256"));
    if (blob && identity && identity->getLength() == 32 &&
        nabu_gpu_userprobe_addon_valid(static_cast<const uint8_t *>(blob->getBytesNoCopy()), blob->getLength())) {
      SHA256_CTX context;
      uint8_t digest[32];
      SHA256_Init(&context);
      SHA256_Update(&context, blob->getBytesNoCopy(), blob->getLength());
      SHA256_Final(digest, &context);
      if (!memcmp(digest, identity->getBytesNoCopy(), sizeof(digest))) {
        blob->retain();
        nabu_gpu_userprobe_retained = blob;
      }
    }
    chosen->release();
  }
  if (!nabu_gpu_userprobe_retained) return 0;
  *data = static_cast<const uint8_t *>(nabu_gpu_userprobe_retained->getBytesNoCopy());
  *bytes = nabu_gpu_userprobe_retained->getLength();
  return 1;
}

'''
RAM_GATE = '''  uint32_t nabu_probe = 0;
  if (PE_parse_boot_argn("nabu-gpu-userprobe", &nabu_probe, sizeof(nabu_probe)) && nabu_probe == 1)
    return nabu_gpu_userprobe_inline(data, bytes);
'''
DATA_BRANCH = '''\t/* NABU_GPU_USERPROBE_JOB_V1 */
\tuint32_t nabu_probe = 0;
\tif (PE_parse_boot_argn("nabu-gpu-userprobe", &nabu_probe, sizeof(nabu_probe)) && nabu_probe == 1) {
\t\tnative_gpu_addon_install(p, scratch);
\t\tif (native_gpu_addon_files != 2 || native_gpu_addon_failed || native_gpu_addon_error) {
\t\t\tprintf("NabuGPU: userprobe addon refused files=%d failed=%d error=%d render_proof=0\\n",
\t\t\t    native_gpu_addon_files, native_gpu_addon_failed, native_gpu_addon_error);
\t\t\treturn;
\t\t}
\t\tstatic const char source[] = "/private/var/ngpu/daemons";
\t\tstatic const char point[] = "/System/Library/LaunchDaemons";
\t\tnative_gpu_addon_mount(p, scratch, 0x600, source, sizeof(source), point, sizeof(point),
\t\t    "/System/Library/LaunchDaemons/com.apple.backboardd.plist",
\t\t    "/System/Library/LaunchDaemons/org.hackios.nabu-gpu-userprobe.plist",
\t\t    &native_gpu_addon2_stage, &native_gpu_addon2_status);
\t\tprintf("NabuGPU: userprobe addon files=%d written=%d same=%d job_stage=%d job_status=%d render_proof=0\\n",
\t\t    native_gpu_addon_files, native_gpu_addon_written, native_gpu_addon_same,
\t\t    native_gpu_addon2_stage, native_gpu_addon2_status);
\t\treturn;
\t}
'''


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('GPU userprobe source drift: ' + old[:90])
    return text.replace(old, new, 1)


def ram_source(text):
    if RAM_MARKER in text:
        if text.count(RAM_HELPER) != 1 or text.count(RAM_GATE) != 1:
            raise ValueError('GPU userprobe RAM source changed after patching')
        return text
    text = once(text, RAM_ANCHOR, RAM_HELPER + RAM_ANCHOR)
    return once(text, '  *data=nullptr;*bytes=0;\n', '  *data=nullptr;*bytes=0;\n' + RAM_GATE)


def data_source(text, restore=False):
    if DATA_MARKER in text:
        if text.count(DATA_BRANCH) != 1:
            raise ValueError('GPU userprobe Data source changed after patching')
        if text.count(PARENTS_AFTER) != 1 or PARENTS_BEFORE in text:
            raise ValueError('GPU userprobe parent creation changed after patching')
        return text.replace(DATA_BRANCH, '', 1).replace(PARENTS_AFTER, PARENTS_BEFORE, 1) if restore else text
    if restore:
        return text
    text = once(text, PARENTS_BEFORE, PARENTS_AFTER)
    return once(text, DATA_ANCHOR, DATA_ANCHOR + DATA_BRANCH)
