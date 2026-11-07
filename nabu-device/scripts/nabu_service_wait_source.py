"""Observe blocked service threads and Mach destinations outside the log writer."""
import hashlib
from pathlib import Path

CONTRACT = {
    'version': 2,
    'trigger': 'nabu-service-wait=1 or 2 after successful lsd csstore mmap with nabu-ls-mmap=1',
    'targets': ['SpringBoard', 'backboardd', 'runningboardd', 'lsd'],
    'detail_trigger': 'nabu-service-wait=2',
    'detail_targets': ['SpringBoard', 'backboardd', 'runningboardd', 'lsd', 'peer'],
    'fallback_peer_name': 'profiled',
    'stack_thread_filter': 'blocked except workqueue return (trap 368, hint 15)',
    'named_peer_detail': True,
    'peer_identity': 'pid and proc_uniqueid, checked under proc_lock',
    'peer_selection': 'receiver of the longest-persisting lsd special-reply wait, kept until replaced',
    'max_passes': 16,
    'interval_seconds': 10,
    'max_threads_scanned': 128,
    'max_rows_per_process': 32,
    'first_thread_always_sampled': True,
    'priority_stack_rows': 'first lsd row and first peer row before remaining UI threads',
    'max_processes_per_pass': 5,
    'process_selection': 'first matching referenced task per name, or the selected peer pid and uniqueid, per pass',
    'new_worker': True,
    'user_memory_read': 'detail only: frame records of blocked startup callers and peer, once per wait signature and at the final pass',
    'stack_signature': 'proc_uniqueid, tid, pc, lr, trap, receive_name',
    'stack_read_attempts_per_signature': 2,
    'max_frames': 12,
    'max_stack_walks_per_pass': 48,
    'changes_syscall_result': False,
    'ipc_lookup_outside_task_and_scheduler_locks': True,
    'publication_bytes': 131072,
    'maximum_line_bytes': 255,
    'worker_may_block': True,
    'symbols': ['_nabu_service_wait_start', '_nabu_service_wait_snapshot'],
}

MARKER = '\n#define NABU_SERVICE_WAIT_VERSION 2\n'
ANY_MARKER = '\n#define NABU_SERVICE_WAIT_VERSION '
HELPER = r'''
#define NABU_SERVICE_WAIT_VERSION 2
#include <arm/thread.h>
#include <arm64/proc_reg.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_port.h>
#include <kern/clock.h>
#include <kern/misc_protos.h>
#include <kern/turnstile.h>
#include <pexpert/pexpert.h>
#include <vm/vm_map.h>
#include <stdarg.h>
extern int vsnprintf(char *, size_t, const char *, va_list);
struct knote;
extern struct turnstile *filt_ipc_kqueue_turnstile(struct knote *);

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
       NABU_SERVICE_TEXT = 131072, NABU_SERVICE_TARGETS = 5, NABU_SERVICE_LSD = 3,
       NABU_SERVICE_PEER = 4, NABU_SERVICE_FRAMES = 12, NABU_SERVICE_WALKS = 48,
       NABU_SERVICE_WALKED = 256 };
/* A frame-pointer chain longer than this from the saved SP is not a thread stack. */
#define NABU_SERVICE_STACK_SPAN (16ULL << 20)
struct nabu_service_row {
    uint64_t tid, pc, lr, trap, registers[8], receiver_uniqueid;
    unsigned index, state, hint, sampled, peer_status, lookup_status, receiver_match;
    int receiver;
    char name[17], receiver_name[17];
};
/* Detail mode only (nabu-service-wait=2), for startup callers and the selected peer.
 * port_status: 0 not a receive-only wait, 1 special reply port, 2 no name/space,
 * 3 receive translation failed, 4 ordinary receive port.
 * ts_status: 0 not linked to a workloop, 1 inheritor read, 2 turnstile busy.
 * stack_status: 0 not walked, 1 wait signature completed or its retry budget exhausted,
 * 2 chain ended, 3 no map,
 * 4 frame outside the stack bounds, 5 user read failed, 6 chain not ascending,
 * 7 frame budget, 8 pass walk budget or signature history capacity. */
struct nabu_service_detail {
    uint64_t sp, fp, frames[NABU_SERVICE_FRAMES], dest_uniqueid, holder_tid;
    uint64_t holder_uniqueid;
    uintptr_t holder_task;
    unsigned port_status, port_kr, special, link, dest_active, dest_kotype, dest_match;
    unsigned ts_status, ts_flags, frame_count, stack_status, holder_match;
    int dest, holder_pid;
    char dest_name[17];
};
struct nabu_service_task {
    uint64_t uniqueid, sampled_us;
    int pid;
    unsigned status, total, scanned, rows, rotation, slide, vm_status;
    unsigned char uuid[16];
    struct nabu_service_row records[NABU_SERVICE_ROWS];
};
static struct nabu_service_task nabu_service_tasks[NABU_SERVICE_TARGETS];
static struct nabu_service_detail nabu_service_details[NABU_SERVICE_TARGETS][NABU_SERVICE_ROWS];
static ipc_space_t nabu_service_spaces[NABU_SERVICE_TARGETS];
static vm_map_t nabu_service_maps[NABU_SERVICE_TARGETS];
static char nabu_service_draft[NABU_SERVICE_TEXT], nabu_service_published[NABU_SERVICE_TEXT],
            nabu_service_readback[NABU_SERVICE_TEXT];
static unsigned nabu_service_started, nabu_service_launch_complete, nabu_service_result;
static unsigned nabu_service_pass, nabu_service_seen_mask, nabu_service_phase;
static unsigned nabu_service_draft_bytes, nabu_service_dropped_lines;
static unsigned nabu_service_publish_gate, nabu_service_publish_dropped;
static unsigned nabu_service_published_bytes, nabu_service_generation;
static unsigned nabu_service_reader_busy, nabu_service_emitted_generation;
static unsigned nabu_service_detail_mode, nabu_service_walks, nabu_service_walked_count;
struct nabu_service_walk_key {
    uint64_t uniqueid, tid, pc, lr, trap, receive_name;
    unsigned attempts, finished;
};
static struct nabu_service_walk_key nabu_service_walked[NABU_SERVICE_WALKED];
/* Peer chosen from lsd's waits; persistence of each lsd wait across passes. */
static int nabu_service_peer_pid;
static uint64_t nabu_service_peer_uniqueid;
static unsigned nabu_service_peer_count, nabu_service_peer_source;
static char nabu_service_peer_name[17];
static uint64_t nabu_service_wait_tids[NABU_SERVICE_ROWS];
static uint32_t nabu_service_wait_names[NABU_SERVICE_ROWS];
static unsigned nabu_service_wait_counts[NABU_SERVICE_ROWS], nabu_service_wait_rows;
static const char *const nabu_service_names[] = {
    "SpringBoard", "backboardd", "runningboardd", "lsd", "peer"
};

static uint64_t
nabu_service_now(void)
{
    uint64_t nanoseconds = 0;
    absolutetime_to_nanoseconds(mach_absolute_time(), &nanoseconds);
    return nanoseconds / 1000;
}

static int
nabu_service_named(const char *name)
{
    if (!name) return -1;
    for (unsigned index = 0; index < NABU_SERVICE_PEER; ++index)
        if (!strcmp(name, nabu_service_names[index])) return (int)index;
    return -1;
}

static int
nabu_service_target(struct proc *process)
{
    const int named = nabu_service_named(proc_name_address(process));
    if (named >= 0) return named;
    const int peer = __atomic_load_n(&nabu_service_peer_pid, __ATOMIC_RELAXED);
    if (nabu_service_detail_mode && peer <= 0 && !strcmp(proc_name_address(process), "profiled"))
        return NABU_SERVICE_PEER;
    return nabu_service_detail_mode && peer > 0 && proc_pid(process) == peer ? NABU_SERVICE_PEER : -1;
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
    if (target < 0 || (nabu_service_seen_mask & (1U << target)) ||
        (target == NABU_SERVICE_PEER && nabu_service_peer_pid > 0 &&
            proc_uniqueid(process) != nabu_service_peer_uniqueid)) {
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
    if (target == NABU_SERVICE_PEER && nabu_service_peer_pid <= 0) {
        nabu_service_peer_uniqueid = record->uniqueid;
        nabu_service_peer_source = 3; /* Explicit migration service, not inferred from an IPC port. */
        nabu_service_name(nabu_service_peer_name, proc_name_address(process));
        __atomic_store_n(&nabu_service_peer_pid, record->pid, __ATOMIC_RELAXED);
    }
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
    const unsigned detailed = nabu_service_detail_mode;
    if (detailed) {
        /* Frame records are read after every task/proc/thread lock is dropped. */
        vm_map_t map = task->map;
        if (map != VM_MAP_NULL) vm_map_reference(map);
        nabu_service_maps[target] = map;
        record->vm_status = map != VM_MAP_NULL ? 1 : 2;
        record->slide = task->task_shared_region_slide;
        memcpy(record->uuid, task->task_shared_region_uuid, sizeof(record->uuid));
    }
    record->status = 0;
    record->total = task->thread_count > 0 ? (unsigned)task->thread_count : 0;
    const unsigned limit = record->total < NABU_SERVICE_SCAN ? record->total : NABU_SERVICE_SCAN;
    const unsigned pass = __atomic_load_n(&nabu_service_pass, __ATOMIC_RELAXED);
    record->rotation = limit ? ((pass - 1) * NABU_SERVICE_ROWS) % limit : 0;
    thread_t thread;
    queue_iterate(&task->threads, thread, thread_t, task_threads) {
        if (record->scanned >= limit) break;
        const unsigned index = record->scanned++;
        if (index != 0 && (index + limit - record->rotation) % limit >=
            NABU_SERVICE_ROWS - (record->rotation != 0)) continue;
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
                    if (detailed) {
                        struct nabu_service_detail *detail = &nabu_service_details[target][record->rows - 1];
                        detail->sp = (uint64_t)get_saved_state_sp(saved);
                        detail->fp = (uint64_t)get_saved_state_fp(saved);
                    }
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

/* Name a pid only if the found process still owns the expected task. */
static unsigned
nabu_service_proc_name(int pid, uintptr_t expected_task, uint64_t *uniqueid, char output[17])
{
    unsigned matched = 0;
    struct proc *process = proc_find(pid);
    if (process == NULL) return 0;
    proc_lock(process);
    if (!expected_task || (uintptr_t)proc_task(process) == expected_task) {
        if (uniqueid) *uniqueid = proc_uniqueid(process);
        nabu_service_name(output, proc_name_address(process));
        matched = 1;
    }
    proc_unlock(process);
    proc_rele(process);
    return matched;
}

/* Called with the special reply port locked: that lock keeps the knote or stashed
 * turnstile linked. The turnstile lock is only tried, at splsched as it is irq-safe,
 * and a thread inheritor is pinned by the turnstile lock while it is read. */
static void
nabu_service_turnstile(struct turnstile *ts, struct nabu_service_detail *detail)
{
    detail->ts_status = 2;
    spl_t level = splsched();
    if (waitq_lock_try(&ts->ts_waitq)) {
        detail->ts_status = 1;
        detail->ts_flags = (unsigned)ts->ts_inheritor_flags;
        void *inheritor = (void *)ts->ts_inheritor;
        if (inheritor != TURNSTILE_INHERITOR_NULL && (detail->ts_flags & TURNSTILE_INHERITOR_THREAD)) {
            thread_t holder = (thread_t)inheritor;
            detail->holder_tid = thread_tid(holder);
            task_t owner = get_threadtask(holder);
            detail->holder_pid = owner != TASK_NULL ? task_pid(owner) : -1;
            detail->holder_task = (uintptr_t)owner;
        }
        waitq_unlock(&ts->ts_waitq);
    }
    splx(level);
}

/* A receive-only mach_msg2 wait: name the port it receives on and, for a special
 * reply port, the port or workloop its sync IPC is linked to. */
static void
nabu_service_port(unsigned target, const struct nabu_service_row *row, struct nabu_service_detail *detail)
{
    const mach_port_name_t name = (mach_port_name_t)(row->registers[5] >> 32);
    detail->port_status = 2;
    if (name == MACH_PORT_NULL || nabu_service_spaces[target] == IS_NULL) return;
    ipc_port_t port = IP_NULL, dest = IP_NULL;
    const kern_return_t result = ipc_port_translate_receive(nabu_service_spaces[target], name, &port);
    detail->port_kr = (unsigned)result;
    detail->port_status = 3;
    if (result != KERN_SUCCESS) return;
    detail->port_status = 4;
    detail->special = port->ip_specialreply;
    detail->link = port->ip_sync_link_state;
    if (detail->special) {
        detail->port_status = 1;
        struct turnstile *ts = TURNSTILE_NULL;
        if (detail->link == PORT_SYNC_LINK_PORT && port->ip_sync_inheritor_port != IP_NULL) {
            dest = port->ip_sync_inheritor_port;
            ip_reference(dest);
        } else if (detail->link == PORT_SYNC_LINK_WORKLOOP_KNOTE && port->ip_sync_inheritor_knote != NULL) {
            ts = filt_ipc_kqueue_turnstile(port->ip_sync_inheritor_knote);
        } else if (detail->link == PORT_SYNC_LINK_WORKLOOP_STASH) {
            ts = port->ip_sync_inheritor_ts;
        }
        if (ts != TURNSTILE_NULL) nabu_service_turnstile(ts, detail);
    }
    ip_mq_unlock(port);
    if (detail->holder_pid > 0 && detail->holder_task) {
        char holder_name[17] = {0};
        detail->holder_match = nabu_service_proc_name(detail->holder_pid, detail->holder_task,
            &detail->holder_uniqueid, holder_name);
    }
    if (dest == IP_NULL) return;
    uintptr_t receiver_task = 0;
    ip_mq_lock(dest);
    detail->dest_active = ip_active(dest) ? 1 : 0;
    detail->dest_kotype = (unsigned)ip_kotype(dest);
    detail->dest = ipc_port_get_receiver_task_locked(dest, &receiver_task);
    ip_mq_unlock(dest);
    ip_release(dest);
    if (detail->dest > 0 && receiver_task)
        detail->dest_match = nabu_service_proc_name(detail->dest, receiver_task, &detail->dest_uniqueid,
            detail->dest_name);
}

static struct nabu_service_walk_key *
nabu_service_walk_key(unsigned target, const struct nabu_service_row *row)
{
    const uint64_t uniqueid = nabu_service_tasks[target].uniqueid;
    const uint64_t receive_name = row->trap == (uint64_t)-47 ? row->registers[5] >> 32 : 0;
    for (unsigned index = 0; index < nabu_service_walked_count; ++index)
        if (nabu_service_walked[index].uniqueid == uniqueid && nabu_service_walked[index].tid == row->tid &&
            nabu_service_walked[index].pc == row->pc && nabu_service_walked[index].lr == row->lr &&
            nabu_service_walked[index].trap == row->trap &&
            nabu_service_walked[index].receive_name == receive_name) return &nabu_service_walked[index];
    if (nabu_service_walked_count >= NABU_SERVICE_WALKED) return NULL;
    struct nabu_service_walk_key *key = &nabu_service_walked[nabu_service_walked_count++];
    key->uniqueid = uniqueid; key->tid = row->tid; key->pc = row->pc; key->lr = row->lr;
    key->trap = row->trap; key->receive_name = receive_name;
    return key;
}

/* Frame records of a blocked user thread, read through its own map with no lock
 * held. The thread may resume meanwhile: the chain is a best-effort snapshot. */
static void
nabu_service_stack(unsigned target, const struct nabu_service_row *row, struct nabu_service_detail *detail,
    unsigned final_pass)
{
    if (nabu_service_walks >= NABU_SERVICE_WALKS) {
        detail->stack_status = 8;
        return;
    }
    struct nabu_service_walk_key *key = nabu_service_walk_key(target, row);
    if (!final_pass && key == NULL) {
        detail->stack_status = 8;
        return;
    }
    if (!final_pass && (key->finished || key->attempts >= 2)) {
        detail->stack_status = 1;
        return;
    }
    ++nabu_service_walks;
    if (key != NULL) ++key->attempts;
    vm_map_t map = nabu_service_maps[target];
    detail->stack_status = 3;
    if (map == VM_MAP_NULL) return;
    uint64_t fp = detail->fp;
    detail->stack_status = 7;
    while (detail->frame_count < NABU_SERVICE_FRAMES) {
        if (fp == 0) {
            detail->stack_status = 2;
            break;
        }
        if ((fp & 7) || fp < detail->sp || fp - detail->sp > NABU_SERVICE_STACK_SPAN) {
            detail->stack_status = 4;
            break;
        }
        uint64_t record[2] = {0, 0};
        if (vm_map_read_user(map, (vm_map_address_t)fp, record, sizeof(record)) != KERN_SUCCESS) {
            detail->stack_status = 5;
            break;
        }
        detail->frames[detail->frame_count++] = record[1];
        if (record[0] != 0 && record[0] <= fp) {
            detail->stack_status = 6;
            break;
        }
        fp = record[0];
    }
    if (key != NULL && detail->stack_status != 5) key->finished = 1;
}

static unsigned
nabu_service_receive_only(const struct nabu_service_row *row)
{
    return row->sampled == 0 && row->trap == (uint64_t)-47 &&
        !(row->registers[1] & 1) && (row->registers[1] & 2);
}

static void
nabu_service_resolve_detail(unsigned target, unsigned final_pass)
{
    const struct nabu_service_task *record = &nabu_service_tasks[target];
    for (unsigned index = 0; index < record->rows; ++index) {
        const struct nabu_service_row *row = &record->records[index];
        struct nabu_service_detail *detail = &nabu_service_details[target][index];
        if (row->sampled != 0) continue;
        /* An idle workqueue-return thread has no caller work to attribute. Keep
         * its raw row, reserving walks for the actual startup call paths. */
        if (row->trap == 368 && row->hint == 15) continue;
        if (detail->stack_status == 0) nabu_service_stack(target, row, detail, final_pass);
        if (nabu_service_receive_only(row)) nabu_service_port(target, row, detail);
    }
}

/* The peer is the process on the other end of lsd's longest-persisting reply wait
 * (same thread and receive name in consecutive passes). It is kept until another
 * wait persists longer, so the server stays observed after lsd's wait clears. */
static void
nabu_service_pick_peer(void)
{
    const struct nabu_service_task *record = &nabu_service_tasks[NABU_SERVICE_LSD];
    uint64_t tids[NABU_SERVICE_ROWS];
    uint32_t names[NABU_SERVICE_ROWS];
    unsigned counts[NABU_SERVICE_ROWS], rows = 0, best_count = 0, best_source = 0;
    uint64_t best_uniqueid = 0;
    int best = -1;
    if (record->status != 0) {
        nabu_service_wait_rows = 0;
        return;
    }
    for (unsigned index = 0; index < record->rows; ++index) {
        const struct nabu_service_row *row = &record->records[index];
        const struct nabu_service_detail *detail = &nabu_service_details[NABU_SERVICE_LSD][index];
        if (!nabu_service_receive_only(row) || detail->port_status != 1) continue;
        const uint32_t name = (uint32_t)(row->registers[5] >> 32);
        unsigned count = 1;
        for (unsigned previous = 0; previous < nabu_service_wait_rows; ++previous)
            if (nabu_service_wait_tids[previous] == row->tid && nabu_service_wait_names[previous] == name)
                count = nabu_service_wait_counts[previous] + 1;
        tids[rows] = row->tid;
        names[rows] = name;
        counts[rows++] = count;
        int candidate = -1;
        uint64_t candidate_uniqueid = 0;
        unsigned source = 0;
        if (detail->dest_match && detail->dest > 0 && detail->dest != record->pid) {
            candidate = detail->dest;
            candidate_uniqueid = detail->dest_uniqueid;
            source = 1;
        } else if (detail->holder_match && detail->holder_pid > 0 && detail->holder_pid != record->pid) {
            candidate = detail->holder_pid;
            candidate_uniqueid = detail->holder_uniqueid;
            source = 2;
        }
        if (candidate > 0 && count > best_count) {
            best = candidate;
            best_uniqueid = candidate_uniqueid;
            best_count = count;
            best_source = source;
        }
    }
    memcpy(nabu_service_wait_tids, tids, rows * sizeof(tids[0]));
    memcpy(nabu_service_wait_names, names, rows * sizeof(names[0]));
    memcpy(nabu_service_wait_counts, counts, rows * sizeof(counts[0]));
    nabu_service_wait_rows = rows;
    const unsigned same_peer = best == nabu_service_peer_pid && best_uniqueid == nabu_service_peer_uniqueid;
    if (best <= 0 || (!same_peer && best_count <= nabu_service_peer_count)) {
        if (same_peer && best_count > nabu_service_peer_count)
            nabu_service_peer_count = best_count;
        return;
    }
    char name[17] = {0};
    uint64_t verified_uniqueid = 0;
    if (!best_uniqueid || !nabu_service_proc_name(best, 0, &verified_uniqueid, name) ||
        verified_uniqueid != best_uniqueid) return;
    memcpy(nabu_service_peer_name, name, sizeof(name));
    nabu_service_peer_count = best_count;
    nabu_service_peer_source = best_source;
    nabu_service_peer_uniqueid = best_uniqueid;
    __atomic_store_n(&nabu_service_peer_pid, best, __ATOMIC_RELAXED);
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
nabu_service_publish_detail(unsigned pass, unsigned target, unsigned index)
{
    const struct nabu_service_task *record = &nabu_service_tasks[target];
    const struct nabu_service_row *row = &record->records[index];
    const struct nabu_service_detail *detail = &nabu_service_details[target][index];
    if (detail->port_status) {
        nabu_service_format("NabuService: port pass=%u proc=%s pid=%d tid=%llu rcv=%x status=%u kr=%x special=%u link=%u ts=%u ts_flags=%x holder_tid=%llu holder_pid=%d\n",
            pass, nabu_service_names[target], record->pid, (unsigned long long)row->tid,
            (unsigned)(row->registers[5] >> 32), detail->port_status, detail->port_kr, detail->special,
            detail->link, detail->ts_status, detail->ts_flags, (unsigned long long)detail->holder_tid,
            detail->holder_pid);
        if (detail->port_status == 1 && detail->link == PORT_SYNC_LINK_PORT)
            nabu_service_format("NabuService: dest pass=%u proc=%s pid=%d tid=%llu dest=%d active=%u kotype=%u match=%u dest_uniq=%llu dest_name=%s\n",
                pass, nabu_service_names[target], record->pid, (unsigned long long)row->tid, detail->dest,
                detail->dest_active, detail->dest_kotype, detail->dest_match,
                (unsigned long long)detail->dest_uniqueid, detail->dest_name);
    }
    /* 0: not blocked in user space; 1: this wait signature needs no further walk. */
    if (detail->stack_status <= 1) return;
    if (detail->stack_status == 8) {
        nabu_service_format("NabuService: stack pass=%u proc=%s pid=%d tid=%llu status=%u frames=0\n",
            pass, nabu_service_names[target], record->pid, (unsigned long long)row->tid,
            detail->stack_status);
        return;
    }
    nabu_service_format("NabuService: stack pass=%u proc=%s pid=%d tid=%llu status=%u frames=%u sp=%llx fp=%llx\n",
        pass, nabu_service_names[target], record->pid, (unsigned long long)row->tid, detail->stack_status,
        detail->frame_count, (unsigned long long)detail->sp, (unsigned long long)detail->fp);
    for (unsigned part = 0; part * 6 < detail->frame_count; ++part) {
        const uint64_t *frame = detail->frames + part * 6;
        nabu_service_format("NabuService: frames pass=%u proc=%s tid=%llu part=%u f=%llx,%llx,%llx,%llx,%llx,%llx\n",
            pass, nabu_service_names[target], (unsigned long long)row->tid, part,
            (unsigned long long)frame[0], (unsigned long long)frame[1], (unsigned long long)frame[2],
            (unsigned long long)frame[3], (unsigned long long)frame[4], (unsigned long long)frame[5]);
    }
}

static void
nabu_service_publish(unsigned resolved)
{
    const unsigned pass = __atomic_load_n(&nabu_service_pass, __ATOMIC_RELAXED);
    const unsigned targets = nabu_service_detail_mode ? NABU_SERVICE_TARGETS : NABU_SERVICE_PEER;
    nabu_service_draft_bytes = 0;
    nabu_service_dropped_lines = 0;
    nabu_service_format("NabuService: begin pass=%u resolved=%u abs_us=%llu\n", pass, resolved,
        (unsigned long long)nabu_service_now());
    if (nabu_service_detail_mode)
        nabu_service_format("NabuService: peerpick pass=%u pid=%d count=%u source=%u name=%s walks=%u walked=%u uniq=%llu\n",
            pass, __atomic_load_n(&nabu_service_peer_pid, __ATOMIC_RELAXED), nabu_service_peer_count,
            nabu_service_peer_source, nabu_service_peer_name, nabu_service_walks, nabu_service_walked_count,
            (unsigned long long)nabu_service_peer_uniqueid);
    for (unsigned target = 0; target < targets; ++target) {
        const struct nabu_service_task *record = &nabu_service_tasks[target];
        nabu_service_format("NabuService: task pass=%u proc=%s pid=%d uniq=%llu status=%u total=%u scanned=%u rows=%u omitted=%u rotation=%u abs_us=%llu\n",
            pass, nabu_service_names[target], record->pid, (unsigned long long)record->uniqueid,
            record->status, record->total, record->scanned, record->rows,
            record->total > record->rows ? record->total - record->rows : 0, record->rotation,
            (unsigned long long)record->sampled_us);
        const unsigned detailed = nabu_service_detail_mode && record->vm_status != 0;
        if (detailed && record->vm_status) {
            const unsigned char *uuid = record->uuid;
            nabu_service_format("NabuService: vm pass=%u proc=%s pid=%d map=%u slide=%x cache_uuid=%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
                pass, nabu_service_names[target], record->pid, record->vm_status, record->slide,
                uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
                uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
        }
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
            if (row->sampled == 0 && row->trap == (uint64_t)-47 &&
                ((row->registers[1] & 1) || (detailed && nabu_service_receive_only(row)))) {
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
            if (detailed && resolved) nabu_service_publish_detail(pass, target, index);
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
nabu_service_validate_peer(void)
{
    if (nabu_service_peer_pid <= 0) return;
    uint64_t current_uniqueid = 0;
    char current_name[17] = {0};
    if (!nabu_service_proc_name(nabu_service_peer_pid, 0, &current_uniqueid, current_name) ||
        current_uniqueid != nabu_service_peer_uniqueid) {
        nabu_service_peer_pid = 0; nabu_service_peer_uniqueid = 0;
        nabu_service_peer_count = 0; nabu_service_peer_source = 0;
        memset(nabu_service_peer_name, 0, sizeof(nabu_service_peer_name));
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
        nabu_service_walks = 0;
        nabu_service_validate_peer();
        memset(nabu_service_tasks, 0, sizeof(nabu_service_tasks));
        memset(nabu_service_details, 0, sizeof(nabu_service_details));
        memset(nabu_service_spaces, 0, sizeof(nabu_service_spaces));
        memset(nabu_service_maps, 0, sizeof(nabu_service_maps));
        for (unsigned target = 0; target < NABU_SERVICE_TARGETS; ++target) nabu_service_tasks[target].status = 2;
        proc_iterate((1U << 0) | (1U << 2), nabu_service_capture, NULL, nabu_service_filter, NULL);
        nabu_service_publish(0);
        for (unsigned target = 0; target < NABU_SERVICE_TARGETS; ++target) {
            __atomic_store_n(&nabu_service_phase, 10 + target, __ATOMIC_RELAXED);
            nabu_service_resolve(target);
        }
        if (nabu_service_detail_mode) {
            /* Keep both ends' first threads visible even when the UI fills the
             * shared walk budget. Other rows retain rotation and omission counts. */
            for (unsigned target = NABU_SERVICE_LSD; target <= NABU_SERVICE_PEER; ++target) {
                const struct nabu_service_task *record = &nabu_service_tasks[target];
                if (!record->rows || record->vm_status == 0) continue;
                const struct nabu_service_row *row = &record->records[0];
                if (row->sampled == 0 && !(row->trap == 368 && row->hint == 15))
                    nabu_service_stack(target, row, &nabu_service_details[target][0], pass == NABU_SERVICE_PASSES);
            }
            /* Give the lsd call path first use of the bounded stack budget. */
            __atomic_store_n(&nabu_service_phase, 20 + NABU_SERVICE_LSD, __ATOMIC_RELAXED);
            nabu_service_resolve_detail(NABU_SERVICE_LSD, pass == NABU_SERVICE_PASSES);
            for (unsigned target = 0; target < NABU_SERVICE_TARGETS; ++target) {
                if (target == NABU_SERVICE_LSD || nabu_service_tasks[target].vm_status == 0) continue;
                __atomic_store_n(&nabu_service_phase, 20 + target, __ATOMIC_RELAXED);
                nabu_service_resolve_detail(target, pass == NABU_SERVICE_PASSES);
            }
            nabu_service_pick_peer();
        }
        for (unsigned target = 0; target < NABU_SERVICE_TARGETS; ++target) {
            if (nabu_service_spaces[target] != IS_NULL) is_release(nabu_service_spaces[target]);
            if (nabu_service_maps[target] != VM_MAP_NULL) vm_map_deallocate(nabu_service_maps[target]);
        }
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
    if (!PE_parse_boot_argn("nabu-service-wait", &requested, sizeof(requested)) ||
        (requested != 1 && requested != 2)) return;
    if (__atomic_exchange_n(&nabu_service_started, 1, __ATOMIC_ACQ_REL)) return;
    nabu_service_detail_mode = requested == 2;
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
    if ANY_MARKER in text:
        if text.count(ANY_MARKER) != 1 or not text.endswith(injected):
            raise ValueError('Service observer differs from its recorded generator')
        text = text[:-len(injected)]
    return text if restore else text + injected
