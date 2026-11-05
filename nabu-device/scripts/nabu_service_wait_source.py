"""Observe blocked service threads and Mach destinations outside the log writer."""
import hashlib
from pathlib import Path

CONTRACT = {
    'version': 1,
    'trigger': 'nabu-service-wait=1 after successful lsd csstore mmap with nabu-ls-mmap=1',
    'targets': ['SpringBoard', 'backboardd', 'runningboardd', 'lsd'],
    'max_passes': 16,
    'interval_seconds': 10,
    'max_threads_scanned': 128,
    'max_rows_per_process': 32,
    'max_processes_per_pass': 4,
    'process_selection': 'first matching referenced task per name per pass',
    'new_worker': True,
    'user_memory_read': False,
    'changes_syscall_result': False,
    'ipc_lookup_outside_task_and_scheduler_locks': True,
    'publication_bytes': 131072,
    'maximum_line_bytes': 255,
    'worker_may_block': True,
    'symbols': ['_nabu_service_wait_start', '_nabu_service_wait_snapshot'],
}

MARKER = '\n#define NABU_SERVICE_WAIT_VERSION 1\n'
HELPER = r'''
#define NABU_SERVICE_WAIT_VERSION 1
#include <arm/thread.h>
#include <arm64/proc_reg.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_port.h>
#include <kern/clock.h>
#include <kern/misc_protos.h>
#include <pexpert/pexpert.h>
#include <stdarg.h>
extern int vsnprintf(char *, size_t, const char *, va_list);

struct proc;
extern char *proc_name_address(void *);
extern int proc_pid(struct proc *);
extern uint64_t proc_uniqueid(struct proc *);
extern task_t proc_task(struct proc *);
extern void proc_lock(struct proc *);
extern void proc_unlock(struct proc *);
extern struct proc *proc_find(int);
extern void proc_rele(struct proc *);
extern void proc_iterate(unsigned int, int (*)(struct proc *, void *), void *,
    int (*)(struct proc *, void *), void *);
extern void nabu_capture_append(const char *, unsigned);

const char nabu_service_wait_identity[] __attribute__((used)) =
    "NABUSERVICE_SOURCE_SHA256=__NABU_SERVICE_SOURCE_ID__";

enum { NABU_SERVICE_PASSES = 16, NABU_SERVICE_SCAN = 128, NABU_SERVICE_ROWS = 32,
       NABU_SERVICE_TEXT = 131072 };
struct nabu_service_row {
    uint64_t tid, pc, lr, trap, registers[8], receiver_uniqueid;
    unsigned index, state, hint, sampled, peer_status, lookup_status, receiver_match;
    int receiver;
    char name[17], receiver_name[17];
};
struct nabu_service_task {
    uint64_t uniqueid, sampled_us;
    int pid;
    unsigned status, total, scanned, rows, rotation;
    struct nabu_service_row records[NABU_SERVICE_ROWS];
};
static struct nabu_service_task nabu_service_tasks[4];
static ipc_space_t nabu_service_spaces[4];
static char nabu_service_draft[NABU_SERVICE_TEXT], nabu_service_published[NABU_SERVICE_TEXT],
            nabu_service_readback[NABU_SERVICE_TEXT];
static unsigned nabu_service_started, nabu_service_launch_complete, nabu_service_result;
static unsigned nabu_service_pass, nabu_service_seen_mask, nabu_service_phase;
static unsigned nabu_service_draft_bytes, nabu_service_dropped_lines;
static unsigned nabu_service_publish_gate, nabu_service_publish_dropped;
static unsigned nabu_service_published_bytes, nabu_service_generation;
static unsigned nabu_service_reader_busy, nabu_service_emitted_generation;
static const char *const nabu_service_names[] = {
    "SpringBoard", "backboardd", "runningboardd", "lsd"
};

static uint64_t
nabu_service_now(void)
{
    uint64_t nanoseconds = 0;
    absolutetime_to_nanoseconds(mach_absolute_time(), &nanoseconds);
    return nanoseconds / 1000;
}

static int
nabu_service_target(struct proc *process)
{
    const char *name = proc_name_address(process);
    if (!name) return -1;
    for (unsigned index = 0; index < 4; ++index)
        if (!strcmp(name, nabu_service_names[index])) return (int)index;
    return -1;
}

static int
nabu_service_filter(struct proc *process, void *unused)
{
    (void)unused;
    return nabu_service_target(process) >= 0;
}

static void
nabu_service_name(char output[17], const char *name)
{
    unsigned index = 0;
    for (; name && index < 16 && name[index]; ++index) {
        const unsigned char value = (unsigned char)name[index];
        output[index] = value > 0x20 && value < 0x7f && value != '=' ? (char)value : '?';
    }
    output[index] = 0;
}

static int
nabu_service_capture(struct proc *process, void *unused)
{
    (void)unused;
    proc_lock(process);
    const int target = nabu_service_target(process);
    if (target < 0 || (nabu_service_seen_mask & (1U << target))) {
        proc_unlock(process);
        return 0;
    }
    task_t task = proc_task(process);
    if (task == TASK_NULL) {
        proc_unlock(process);
        return 0;
    }
    task_reference(task);
    struct nabu_service_task *record = &nabu_service_tasks[target];
    record->pid = proc_pid(process);
    record->uniqueid = proc_uniqueid(process);
    nabu_service_seen_mask |= 1U << target;
    proc_unlock(process);
    record->status = 1;
    if (!task_lock_try(task)) {
        task_deallocate(task);
        return 0;
    }
    ipc_space_t space = task->itk_space;
    if (space != IS_NULL) is_reference(space);
    nabu_service_spaces[target] = space;
    record->status = 0;
    record->total = task->thread_count > 0 ? (unsigned)task->thread_count : 0;
    const unsigned limit = record->total < NABU_SERVICE_SCAN ? record->total : NABU_SERVICE_SCAN;
    const unsigned pass = __atomic_load_n(&nabu_service_pass, __ATOMIC_RELAXED);
    record->rotation = limit ? ((pass - 1) * NABU_SERVICE_ROWS) % limit : 0;
    thread_t thread;
    queue_iterate(&task->threads, thread, thread_t, task_threads) {
        if (record->scanned >= limit) break;
        const unsigned index = record->scanned++;
        if ((index + limit - record->rotation) % limit >= NABU_SERVICE_ROWS) continue;
        if (record->rows >= NABU_SERVICE_ROWS) break;
        struct nabu_service_row *row = &record->records[record->rows++];
        row->tid = thread_tid(thread);
        row->index = index;
        row->sampled = 1;
        row->receiver = -1;
        row->peer_status = 8;
        row->lookup_status = 0xffffffffU;
        spl_t level = splsched();
        if (simple_lock_try(&thread->sched_lock, &thread_lck_grp)) {
            row->state = (unsigned)thread->state;
            row->hint = (unsigned)thread->block_hint;
            char name[64] = {0};
            thread_get_thread_name(thread, name);
            nabu_service_name(row->name, name);
            if (row->state & (TH_TERMINATE | TH_TERMINATE2)) row->sampled = 5;
            else if (row->state & (TH_RUN | TH_WAKING)) row->sampled = 2;
            else if (!(row->state & TH_WAIT)) row->sampled = 4;
            else {
                arm_saved_state_t *saved = thread->machine.upcb;
                row->sampled = 3;
                if (saved != NULL && is_saved_state64(saved) && PSR64_IS_USER64(get_saved_state_cpsr(saved))) {
                    row->pc = (uint64_t)get_saved_state_pc(saved);
                    row->lr = (uint64_t)get_saved_state_lr(saved);
                    row->trap = (uint64_t)get_saved_state_reg(saved, 16);
                    for (unsigned argument = 0; argument < 8; ++argument)
                        row->registers[argument] = (uint64_t)get_saved_state_reg(saved, argument);
                    row->sampled = 0;
                }
            }
            thread_unlock(thread);
        }
        splx(level);
    }
    task_unlock(task);
    record->sampled_us = nabu_service_now();
    task_deallocate(task);
    return 0;
}

static void
nabu_service_resolve(unsigned target)
{
    struct nabu_service_task *record = &nabu_service_tasks[target];
    for (unsigned index = 0; index < record->rows; ++index) {
        struct nabu_service_row *row = &record->records[index];
        row->peer_status = 1;
        if (row->sampled != 0 || row->trap != (uint64_t)-47) continue;
        row->peer_status = 5;
        if (!(row->registers[1] & 1)) continue;
        const mach_port_name_t remote = (mach_port_name_t)row->registers[3];
        row->peer_status = 2;
        if (remote == MACH_PORT_NULL) continue;
        row->peer_status = 3;
        if (nabu_service_spaces[target] == IS_NULL) continue;
        ipc_port_t port = IP_NULL;
        const kern_return_t result = ipc_port_translate_send(nabu_service_spaces[target], remote, &port);
        row->lookup_status = (unsigned)result;
        row->peer_status = 4;
        if (result != KERN_SUCCESS) continue;
        uintptr_t receiver_task = 0;
        row->receiver = ipc_port_get_receiver_task_locked(port, &receiver_task);
        ip_mq_unlock(port);
        row->peer_status = 6;
        if (row->receiver <= 0 || !receiver_task) continue;
        row->peer_status = 7;
        struct proc *peer = proc_find(row->receiver);
        if (peer == NULL) continue;
        proc_lock(peer);
        if ((uintptr_t)proc_task(peer) == receiver_task) {
            row->receiver_uniqueid = proc_uniqueid(peer);
            row->receiver_match = 1;
            nabu_service_name(row->receiver_name, proc_name_address(peer));
            row->peer_status = 0;
        }
        proc_unlock(peer);
        proc_rele(peer);
    }
}

static void
nabu_service_format(const char *format, ...)
{
    char line[256];
    va_list arguments;
    va_start(arguments, format);
    const int bytes = vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    if (bytes <= 0 || (unsigned)bytes >= sizeof(line) ||
        (unsigned)bytes > NABU_SERVICE_TEXT - nabu_service_draft_bytes) {
        ++nabu_service_dropped_lines;
        return;
    }
    memcpy(nabu_service_draft + nabu_service_draft_bytes, line, (unsigned)bytes);
    nabu_service_draft_bytes += (unsigned)bytes;
}

static void
nabu_service_publish(unsigned resolved)
{
    const unsigned pass = __atomic_load_n(&nabu_service_pass, __ATOMIC_RELAXED);
    nabu_service_draft_bytes = 0;
    nabu_service_dropped_lines = 0;
    nabu_service_format("NabuService: begin pass=%u resolved=%u abs_us=%llu\n", pass, resolved,
        (unsigned long long)nabu_service_now());
    for (unsigned target = 0; target < 4; ++target) {
        const struct nabu_service_task *record = &nabu_service_tasks[target];
        nabu_service_format("NabuService: task pass=%u proc=%s pid=%d uniq=%llu status=%u total=%u scanned=%u rows=%u omitted=%u rotation=%u abs_us=%llu\n",
            pass, nabu_service_names[target], record->pid, (unsigned long long)record->uniqueid,
            record->status, record->total, record->scanned, record->rows,
            record->total > record->rows ? record->total - record->rows : 0, record->rotation,
            (unsigned long long)record->sampled_us);
        for (unsigned index = 0; index < record->rows; ++index) {
            const struct nabu_service_row *row = &record->records[index];
            nabu_service_format("NabuService: row pass=%u proc=%s pid=%d uniq=%llu tid=%llu index=%u sampled=%u state=%x hint=%u name=%s pc=%llx lr=%llx trap=%llx\n",
                pass, nabu_service_names[target], record->pid, (unsigned long long)record->uniqueid,
                (unsigned long long)row->tid, row->index, row->sampled, row->state, row->hint,
                row->name, (unsigned long long)row->pc, (unsigned long long)row->lr,
                (unsigned long long)row->trap);
            nabu_service_format("NabuService: peer pass=%u proc=%s pid=%d uniq=%llu tid=%llu receiver=%d peer=%u kr=%x receiver_uniq=%llu receiver_match=%u receiver_name=%s\n",
                pass, nabu_service_names[target], record->pid, (unsigned long long)record->uniqueid,
                (unsigned long long)row->tid, row->receiver, row->peer_status, row->lookup_status,
                (unsigned long long)row->receiver_uniqueid, row->receiver_match, row->receiver_name);
            if (row->sampled == 0 && row->trap == (uint64_t)-47 && (row->registers[1] & 1)) {
                nabu_service_format("NabuService: args0 pass=%u proc=%s pid=%d uniq=%llu tid=%llu x0=%llx x1=%llx x2=%llx x3=%llx\n",
                    pass, nabu_service_names[target], record->pid, (unsigned long long)record->uniqueid,
                    (unsigned long long)row->tid, (unsigned long long)row->registers[0],
                    (unsigned long long)row->registers[1], (unsigned long long)row->registers[2],
                    (unsigned long long)row->registers[3]);
                nabu_service_format("NabuService: args1 pass=%u proc=%s pid=%d uniq=%llu tid=%llu x4=%llx x5=%llx x6=%llx x7=%llx\n",
                    pass, nabu_service_names[target], record->pid, (unsigned long long)record->uniqueid,
                    (unsigned long long)row->tid, (unsigned long long)row->registers[4],
                    (unsigned long long)row->registers[5], (unsigned long long)row->registers[6],
                    (unsigned long long)row->registers[7]);
            }
        }
    }
    nabu_service_format("NabuService: end pass=%u resolved=%u seen_mask=%x dropped_lines=%u abs_us=%llu\n",
        pass, resolved, nabu_service_seen_mask, nabu_service_dropped_lines,
        (unsigned long long)nabu_service_now());
    if (!__atomic_exchange_n(&nabu_service_publish_gate, 1, __ATOMIC_ACQUIRE)) {
        memcpy(nabu_service_published, nabu_service_draft, nabu_service_draft_bytes);
        nabu_service_published_bytes = nabu_service_draft_bytes;
        ++nabu_service_generation;
        __atomic_store_n(&nabu_service_publish_gate, 0, __ATOMIC_RELEASE);
    } else {
        __atomic_fetch_add(&nabu_service_publish_dropped, 1, __ATOMIC_RELAXED);
    }
}

static void
nabu_service_worker(void *unused, wait_result_t result)
{
    (void)unused;
    (void)result;
    thread_set_thread_name(current_thread(), "nabu_service_wait");
    for (unsigned pass = 1; pass <= NABU_SERVICE_PASSES; ++pass) {
        __atomic_store_n(&nabu_service_pass, pass, __ATOMIC_RELAXED);
        __atomic_store_n(&nabu_service_phase, 1, __ATOMIC_RELAXED);
        nabu_service_seen_mask = 0;
        memset(nabu_service_tasks, 0, sizeof(nabu_service_tasks));
        memset(nabu_service_spaces, 0, sizeof(nabu_service_spaces));
        for (unsigned target = 0; target < 4; ++target) nabu_service_tasks[target].status = 2;
        proc_iterate((1U << 0) | (1U << 2), nabu_service_capture, NULL, nabu_service_filter, NULL);
        nabu_service_publish(0);
        for (unsigned target = 0; target < 4; ++target) {
            __atomic_store_n(&nabu_service_phase, 10 + target, __ATOMIC_RELAXED);
            nabu_service_resolve(target);
        }
        for (unsigned target = 0; target < 4; ++target)
            if (nabu_service_spaces[target] != IS_NULL) is_release(nabu_service_spaces[target]);
        nabu_service_publish(1);
        __atomic_store_n(&nabu_service_phase, 2, __ATOMIC_RELAXED);
        if (pass < NABU_SERVICE_PASSES) {
            assert_wait_timeout((event_t)&nabu_service_started, THREAD_UNINT, 10, NSEC_PER_SEC);
            thread_block(THREAD_CONTINUE_NULL);
        }
    }
    __atomic_store_n(&nabu_service_phase, 3, __ATOMIC_RELAXED);
    thread_terminate_self();
}

__attribute__((noinline)) void
nabu_service_wait_start(void)
{
    unsigned requested = 0;
    if (!PE_parse_boot_argn("nabu-service-wait", &requested, sizeof(requested)) || requested != 1) return;
    if (__atomic_exchange_n(&nabu_service_started, 1, __ATOMIC_ACQ_REL)) return;
    thread_t worker = THREAD_NULL;
    const kern_return_t result = kernel_thread_start_priority(nabu_service_worker, NULL, MINPRI_KERNEL, &worker);
    if (result == KERN_SUCCESS) thread_deallocate(worker);
    __atomic_store_n(&nabu_service_result, (unsigned)result, __ATOMIC_RELAXED);
    __atomic_store_n(&nabu_service_launch_complete, 1, __ATOMIC_RELEASE);
}

__attribute__((noinline)) void
nabu_service_wait_snapshot(void)
{
    if (!__atomic_load_n(&nabu_service_started, __ATOMIC_ACQUIRE) ||
        __atomic_exchange_n(&nabu_service_reader_busy, 1, __ATOMIC_ACQUIRE)) return;
    char pulse[256];
    int count = snprintf(pulse, sizeof(pulse),
        "NabuService: pulse pass=%u phase=%u launch_complete=%u result=%x publish_dropped=%u\n",
        __atomic_load_n(&nabu_service_pass, __ATOMIC_RELAXED),
        __atomic_load_n(&nabu_service_phase, __ATOMIC_RELAXED),
        __atomic_load_n(&nabu_service_launch_complete, __ATOMIC_ACQUIRE),
        __atomic_load_n(&nabu_service_result, __ATOMIC_RELAXED),
        __atomic_load_n(&nabu_service_publish_dropped, __ATOMIC_RELAXED));
    if (count > 0 && (unsigned)count < sizeof(pulse)) nabu_capture_append(pulse, (unsigned)count);
    unsigned bytes = 0;
    if (!__atomic_exchange_n(&nabu_service_publish_gate, 1, __ATOMIC_ACQUIRE)) {
        if (nabu_service_generation != nabu_service_emitted_generation) {
            bytes = nabu_service_published_bytes;
            memcpy(nabu_service_readback, nabu_service_published, bytes);
            nabu_service_emitted_generation = nabu_service_generation;
        }
        __atomic_store_n(&nabu_service_publish_gate, 0, __ATOMIC_RELEASE);
    }
    for (unsigned start = 0; start < bytes;) {
        unsigned end = start;
        while (end < bytes && nabu_service_readback[end] != '\n') ++end;
        if (end < bytes) ++end;
        nabu_capture_append(nabu_service_readback + start, end - start);
        start = end;
    }
    __atomic_store_n(&nabu_service_reader_busy, 0, __ATOMIC_RELEASE);
}
'''


def source(text, restore=False):
    identity = hashlib.sha256(Path(__file__).read_bytes().replace(b'\r\n', b'\n')).hexdigest()
    injected = HELPER.replace('__NABU_SERVICE_SOURCE_ID__', identity)
    if MARKER in text:
        if text.count(MARKER) != 1 or not text.endswith(injected):
            raise ValueError('Service observer differs from its recorded generator')
        text = text[:-len(injected)]
    return text if restore else text + injected
