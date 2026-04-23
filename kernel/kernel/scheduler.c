#include <kernel/sched.h>
#include <kernel/process.h>
#include <kernel/serial.h>
#include <stdint.h>
#include <stdio.h>

const int queue_slices[NUM_QUEUES] = {5, 10, 20};

static task_t *queue_heads[NUM_QUEUES];
static task_t *queue_tails[NUM_QUEUES];
static bool scheduler_enabled = false;

volatile task_t *next_task_ptr = NULL;

extern task_t *idle_process;
extern uint32_t timer_get_ticks(void);

static inline void irq_save_disable(uint32_t *flags) {
    asm volatile("pushf; cli; pop %0" : "=r"(*flags) :: "memory");
}

static inline void irq_restore(uint32_t flags) {
    asm volatile("push %0; popf" :: "r"(flags) : "memory", "cc");
}

static void _enqueue_locked(task_t *task, int level) {
    task->queue_level = level;
    task->next = NULL;
    task->prev = queue_tails[level];
    if (queue_tails[level])
        queue_tails[level]->next = task;
    else
        queue_heads[level] = task;
    queue_tails[level] = task;
}

static void _dequeue_locked(task_t *task) {
    int level = task->queue_level;
    if (task->prev)
        task->prev->next = task->next;
    else
        queue_heads[level] = task->next;
    if (task->next)
        task->next->prev = task->prev;
    else
        queue_tails[level] = task->prev;
    task->next = NULL;
    task->prev = NULL;
}

static task_t *_pick_next_locked(void) {
    for (int q = 0; q < NUM_QUEUES; q++) {
        if (queue_heads[q])
            return queue_heads[q];
    }
    return idle_process;
}

static void _serial_write_int(int n) {
    char buf[12];
    int i = 11;
    buf[i] = '\0';
    if (n == 0) { buf[--i] = '0'; }
    while (n > 0) { buf[--i] = '0' + n % 10; n /= 10; }
    serial_writestring(COM1, buf + i);
}

static void _log_demotion(int pid, const char *name, int from, int to) {
    serial_writestring(COM1, "MLFQ: PID ");
    _serial_write_int(pid);
    serial_writestring(COM1, " (");
    serial_writestring(COM1, name);
    serial_writestring(COM1, ") demoted q");
    _serial_write_int(from);
    serial_writestring(COM1, " -> q");
    _serial_write_int(to);
    serial_writestring(COM1, "\n");
}

static void _boost_all_locked(void) {
    for (int q = 1; q < NUM_QUEUES; q++) {
        task_t *t = queue_heads[q];
        while (t) {
            task_t *next = t->next;
            if (t != idle_process) {
                _dequeue_locked(t);
                t->time_remaining = queue_slices[0];
                _enqueue_locked(t, 0);
            }
            t = next;
        }
    }
}

void scheduler_init(void) {
    for (int q = 0; q < NUM_QUEUES; q++) {
        queue_heads[q] = NULL;
        queue_tails[q] = NULL;
    }
    scheduler_enabled = true;
}

void scheduler_enqueue(task_t *task) {
    if (!task || task->state != TASK_RUNNING)
        return;

    uint32_t flags;
    irq_save_disable(&flags);
    _enqueue_locked(task, task->queue_level);
    irq_restore(flags);
}

void scheduler_dequeue(task_t *task) {
    if (!task) return;

    uint32_t flags;
    irq_save_disable(&flags);
    _dequeue_locked(task);
    irq_restore(flags);
}

task_t *scheduler_pick_next(void) {
    uint32_t flags;
    irq_save_disable(&flags);
    task_t *next = _pick_next_locked();
    irq_restore(flags);
    return next;
}

static int tick_count = 0;

void scheduler_tick(void) {
    if (!scheduler_enabled)
        return;

    tick_count++;

    if (tick_count % MLFQ_BOOST_INTERVAL == 0)
        _boost_all_locked();

    task_t *current = process_current();
    if (!current) {
        serial_writestring(COM1, "SCHED: No current task!\n");
        return;
    }

    if (tick_count % 100 == 0)
        printf("Tick %d: PID %d q%d time_rem=%d\n",
               tick_count, current->pid, current->queue_level, current->time_remaining);

    if (current->time_remaining > 0)
        current->time_remaining--;

    if (current->time_remaining == 0)
        resched_current();
}

void schedule(bool voluntary) {
    if (!scheduler_enabled)
        return;

    uint32_t flags;
    irq_save_disable(&flags);

    task_t *prev = process_current();

    if (prev && prev->state == TASK_RUNNING) {
        int new_level = prev->queue_level;
        if (!voluntary && new_level < NUM_QUEUES - 1) {
            new_level++;
            _log_demotion(prev->pid, prev->name, prev->queue_level, new_level);
        }
        _dequeue_locked(prev);
        prev->time_remaining = queue_slices[new_level];
        _enqueue_locked(prev, new_level);
    }

    task_t *next = _pick_next_locked();

    if (!next || next == prev) {
        irq_restore(flags);
        return;
    }

    next->time_remaining = queue_slices[next->queue_level];
    next->stats.exec_start = timer_get_ticks();

    if (prev) {
        if (voluntary)
            prev->stats.nvcsw++;
        else
            prev->stats.nivcsw++;
    }

    next_task_ptr = next;
    irq_restore(flags);
}

void resched_current(void) {
    task_t *current = process_current();
    if (current)
        current->time_remaining = 0;
    schedule(false);
}
