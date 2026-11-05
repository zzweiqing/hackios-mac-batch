"""Reversible, runtime-disabled tracing of LaunchServices file-backed mmap calls."""
import hashlib
from pathlib import Path

CONTRACT = {
    'version': 1,
    'trigger': 'nabu-ls-mmap=1',
    'max_calls': 64,
    'symbols': ['_nabu_ui_watch_ls_mmap_enter', '_nabu_ui_watch_ls_mmap_exit'],
    'source': 'bsd/kern/kern_mman.c',
    'user_memory_read': False,
    'changes_mmap_result': False,
    'entry_stage': 'vnode acquired and file type checked, before access-time update',
    'exit_stage': 'mmap common return, after pager and fileproc cleanup',
    'filename_prefix': 'com.apple.LaunchServices-',
    'filename_suffix': '-v2.csstore',
    'clock': 'mach_absolute_time converted to microseconds',
}

HELPER = r'''#define NABU_LS_MMAP_OBSERVER_VERSION 1
#include <pexpert/pexpert.h>
#include <kern/clock.h>
#include <kern/thread.h>

extern char *proc_name_address(void *);
extern void nabu_service_wait_start(void);

const char nabu_ls_mmap_source_identity[] __attribute__((used)) =
    "NABULSMAP_SOURCE_SHA256=__NABU_LS_MMAP_SOURCE_ID__";

static int nabu_ls_mmap_enabled = -1;
static unsigned nabu_ls_mmap_reserved;
static unsigned nabu_ls_mmap_dropped;
static unsigned nabu_ls_mmap_budget_reported;

static uint64_t
nabu_ls_mmap_time(void)
{
    uint64_t nanoseconds = 0;
    absolutetime_to_nanoseconds(mach_absolute_time(), &nanoseconds);
    return nanoseconds / 1000;
}

__attribute__((noinline)) unsigned
nabu_ui_watch_ls_mmap_enter(proc_t process, const struct mmap_args *arguments, vnode_t vnode)
{
    int enabled = __atomic_load_n(&nabu_ls_mmap_enabled, __ATOMIC_RELAXED);
    if (enabled < 0) {
        unsigned requested = 0;
        PE_parse_boot_argn("nabu-ls-mmap", &requested, sizeof(requested));
        enabled = requested == 1;
        __atomic_store_n(&nabu_ls_mmap_enabled, enabled, __ATOMIC_RELAXED);
    }
    if (!enabled || !process || !arguments || !vnode) return 0;
    const char *filename = vnode_getname(vnode);
    if (!filename) return 0;
    const char *prefix = "com.apple.LaunchServices-";
    const char *suffix = "-v2.csstore";
    const size_t length = strlen(filename);
    const size_t prefix_length = strlen(prefix), suffix_length = strlen(suffix);
    const int matches = length > prefix_length + suffix_length &&
        !strncmp(filename, prefix, prefix_length) &&
        !strcmp(filename + length - suffix_length, suffix);
    vnode_putname(filename);
    if (!matches) return 0;
    unsigned observed = __atomic_load_n(&nabu_ls_mmap_reserved, __ATOMIC_RELAXED);
    unsigned call = 0;
    for (unsigned attempt = 0; attempt < 4 && observed < 64; ++attempt) {
        if (__atomic_compare_exchange_n(&nabu_ls_mmap_reserved, &observed, observed + 1,
                0, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
            call = observed + 1;
            break;
        }
    }
    if (!call) {
        __atomic_fetch_add(&nabu_ls_mmap_dropped, 1, __ATOMIC_RELAXED);
        if (!__atomic_exchange_n(&nabu_ls_mmap_budget_reported, 1, __ATOMIC_RELAXED))
            printf("NabuLSMap: limited reserved=%u dropped=%u max_calls=64\n",
                __atomic_load_n(&nabu_ls_mmap_reserved, __ATOMIC_RELAXED),
                __atomic_load_n(&nabu_ls_mmap_dropped, __ATOMIC_RELAXED));
        return 0;
    }
    char name[17];
    const char *raw_name = proc_name_address(process);
    unsigned index = 0;
    for (; raw_name && index < 16 && raw_name[index]; ++index) {
        unsigned char character = (unsigned char)raw_name[index];
        name[index] = character > 0x20 && character < 0x7f && character != '=' ? character : '?';
    }
    name[index] = 0;
    printf("NabuLSMap: enter call=%u pid=%d uniq=%llu tid=%llu proc=%s abs_us=%llu vp=%p off=%lld len=%llu prot=%x flags=%x\n",
        call, proc_getpid(process), (unsigned long long)proc_uniqueid(process),
        (unsigned long long)thread_tid(current_thread()), name,
        (unsigned long long)nabu_ls_mmap_time(), vnode, (long long)arguments->pos,
        (unsigned long long)arguments->len, (unsigned)arguments->prot, (unsigned)arguments->flags);
    return call;
}

__attribute__((noinline)) void
nabu_ui_watch_ls_mmap_exit(unsigned call, proc_t process, int error, int mapped, user_addr_t address)
{
    if (!call) return;
    printf("NabuLSMap: exit call=%u pid=%d uniq=%llu tid=%llu abs_us=%llu error=%d mapped=%u addr=%llx\n",
        call, proc_getpid(process), (unsigned long long)proc_uniqueid(process),
        (unsigned long long)thread_tid(current_thread()),
        (unsigned long long)nabu_ls_mmap_time(), error, (unsigned)(!error && mapped),
        (unsigned long long)(error || !mapped ? 0 : address));
    const char *process_name = proc_name_address(process);
    if (!error && mapped && process_name && !strcmp(process_name, "lsd"))
        nabu_service_wait_start();
}

'''

SIGNATURE = 'int\nmmap(proc_t p, struct mmap_args *uap, user_addr_t *retval)\n{\n'
LOCAL = '\tint num_retries = 0;\n'
ENTER = '\t\tAUDIT_ARG(vnpath, vp, ARG_VNODE1);\n'
SUCCESS = '\t\t*retval = user_addr + pageoff;\n'
EXIT = '\treturn error;\n}\n\nint\nmsync('


def pairs():
    identity = hashlib.sha256(Path(__file__).read_bytes().replace(b'\r\n', b'\n')).hexdigest()
    helper = HELPER.replace('__NABU_LS_MMAP_SOURCE_ID__', identity)
    return (
        (SIGNATURE, helper + SIGNATURE),
        (LOCAL, LOCAL + '\tunsigned nabu_ls_mmap_call = 0;\n\tint nabu_ls_mmap_mapped = 0;\n'
                       '\tuser_addr_t nabu_ls_mmap_address = 0;\n'),
        (ENTER, ENTER + '\t\tnabu_ls_mmap_call = nabu_ui_watch_ls_mmap_enter(p, uap, vp);\n'),
        (SUCCESS, SUCCESS + '\t\tnabu_ls_mmap_mapped = 1;\n\t\tnabu_ls_mmap_address = *retval;\n'),
        (EXIT, '\tnabu_ui_watch_ls_mmap_exit(nabu_ls_mmap_call, p, error, nabu_ls_mmap_mapped, nabu_ls_mmap_address);\n' + EXIT),
    )


def source(text, restore=False):
    changes = pairs()
    if 'NABU_LS_MMAP_OBSERVER_VERSION' in text:
        for before, after in reversed(changes):
            if text.count(after) != 1:
                raise ValueError('LaunchServices mmap observer changed after injection')
            text = text.replace(after, before, 1)
    elif restore:
        return text
    if restore:
        return text
    for before, after in changes:
        if text.count(before) != 1:
            raise ValueError('LaunchServices mmap source anchor changed: ' + before[:80])
        text = text.replace(before, after, 1)
    return text
