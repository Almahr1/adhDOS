#include <kernel/sched.h>
#include <kernel/process.h>
#include <kernel/serial.h>
#include <stdio.h>

static task_t *ready_queue_head = NULL;
static task_t *ready_queue_tail = NULL;
static bool scheduler_enabled = false;

// Global pointer for task switching - accessed by assembly code
// When set to non-NULL, assembly stub will switch to this task's stack
extern volatile task_t *next_task_ptr = NULL;

void scheduler_init(void) {
    ready_queue_head = NULL;
    ready_queue_tail = NULL;
    scheduler_enabled = true;
}

void scheduler_enqueue(task_t *task) {
    if (!task || task->state != TASK_RUNNING) {
        return;
    }

    task->next = NULL;
    task->prev = ready_queue_tail;

    if (ready_queue_tail) {
        ready_queue_tail->next = task;
    } else {
        ready_queue_head = task;
    }

    ready_queue_tail = task;
}

void scheduler_dequeue(task_t *task) {
    if (!task) return;

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
}

task_t* scheduler_pick_next(void) {
    task_t *current = process_current();
    task_t *next = ready_queue_head;

    printf("scheduler_pick_next: current PID=%d, ready_queue_head PID=%d\n",
           current ? current->pid : -1,
           next ? next->pid : -1);

    if (!next) {
        printf("  No tasks in ready queue, staying with current\n");
        return current;
    }

    if (next == current && next->next) {
        next = next->next;
        printf("  Current is at head, picking next: PID=%d\n", next->pid);
    } else {
        printf("  Picking head: PID=%d\n", next->pid);
    }

    return next;
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

void schedule(void) {
    if (!scheduler_enabled) {
        return;
    }

    task_t *prev = process_current();
    task_t *next = scheduler_pick_next();

    if (!prev || !next) {
        serial_writestring(COM1, "schedule: prev or next is NULL\n");
        return;
    }

    if (prev == next) {
        return;
    }

    serial_writestring(COM1, "SCHED: Switching tasks\n");

    if (prev && prev->state == TASK_RUNNING) {
        scheduler_dequeue(prev);
        scheduler_enqueue(prev);
        prev->time_remaining = prev->time_slice;
    }

    if (next) {
        next->time_remaining = next->time_slice;
    }

    if (prev != next) {
        prev->stats.nivcsw++;
        next->stats.exec_start = 0;

        serial_writestring(COM1, "SCHED: Setting next_task_ptr for context switch\n");
        next_task_ptr = next;
    }
}

void resched_current(void) {
    task_t *current = process_current();
    if (current) {
        current->time_remaining = 0;
    }
    schedule();
}
