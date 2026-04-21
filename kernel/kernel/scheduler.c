#include <kernel/sched.h>
#include <kernel/process.h>
#include <kernel/serial.h>
#include <stdint.h>
#include <stdio.h>

static task_t *ready_queue_head = NULL;
static task_t *ready_queue_tail = NULL;
static bool scheduler_enabled = false;

// Global pointer for task switching - accessed by assembly code
volatile task_t *next_task_ptr = NULL;

extern task_t *idle_process;
extern uint32_t timer_get_ticks(void);

static inline void irq_save_disable(uint32_t *flags) {
    asm volatile("pushf; cli; pop %0" : "=r"(*flags) :: "memory");
}

static inline void irq_restore(uint32_t flags) {
    asm volatile("push %0; popf" :: "r"(flags) : "memory", "cc");
}

void scheduler_init(void) {
    ready_queue_head = NULL;
    ready_queue_tail = NULL;
    scheduler_enabled = true;
}

void scheduler_enqueue(task_t *task) {
    if (!task || task->state != TASK_RUNNING) {
        return;
    }

    uint32_t flags;
    irq_save_disable(&flags);

    task->next = NULL;
    task->prev = ready_queue_tail;

    if (ready_queue_tail) {
        ready_queue_tail->next = task;
    } else {
        ready_queue_head = task;
    }

    ready_queue_tail = task;

    irq_restore(flags);
}

void scheduler_dequeue(task_t *task) {
    if (!task) return;

    uint32_t flags;
    irq_save_disable(&flags);

    if (task->prev) {
        task->prev->next = task->next;
    } else {
        ready_queue_head = task->next;
    }

    if (task->next) {
        task->next->prev = task->prev;
    } else {
        ready_queue_tail = task->prev;
    }

    task->next = NULL;
    task->prev = NULL;

    irq_restore(flags);
}

task_t* scheduler_pick_next(void) {
    task_t *current = process_current();

    if (!ready_queue_head) {
        return idle_process ? idle_process : current;
    }

    // Pick the highest-priority (lowest number) task, skipping current
    // so we don't stay on the same task when others are ready.
    task_t *best = NULL;
    for (task_t *t = ready_queue_head; t; t = t->next) {
        if (t == current) continue;
        if (!best || t->priority < best->priority) {
            best = t;
        }
    }

    // Only current is in the queue - run it again.
    return best ? best : current;
}

static int tick_count = 0;

void scheduler_tick(void) {
    if (!scheduler_enabled) {
        return;
    }

    tick_count++;

    task_t *current = process_current();
    if (!current) {
        serial_writestring(COM1, "SCHED: No current task!\n");
        return;
    }

    if (current->time_remaining > 0) {
        current->time_remaining--;
    }

    if (tick_count % 100 == 0) {
        printf("Tick %d: PID %d, time_remaining=%d\n",
               tick_count, current->pid, current->time_remaining);
    }

    if (current->time_remaining == 0) {
        printf("Time slice expired for PID %d\n", current->pid);
        resched_current();
    }
}

void schedule(bool voluntary) {
    if (!scheduler_enabled) {
        return;
    }

    task_t *prev = process_current();
    task_t *next = scheduler_pick_next();

    if (!prev || !next || prev == next) {
        return;
    }

    if (prev->state == TASK_RUNNING) {
        scheduler_dequeue(prev);
        scheduler_enqueue(prev);
        prev->time_remaining = prev->time_slice;
    }

    next->time_remaining = next->time_slice;
    next->stats.exec_start = timer_get_ticks();

    if (voluntary) {
        prev->stats.nvcsw++;
    } else {
        prev->stats.nivcsw++;
    }

    next_task_ptr = next;
}

void resched_current(void) {
    task_t *current = process_current();
    if (current) {
        current->time_remaining = 0;
    }
    schedule(false);
}
