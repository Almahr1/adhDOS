#ifndef SCHED_H
#define SCHED_H

#include <kernel/process.h>

#define DEFAULT_TIME_SLICE 10
#define IDLE_PRIORITY 255

void scheduler_init(void);
void scheduler_tick(void);
void schedule(void);

task_t* scheduler_pick_next(void);
void scheduler_enqueue(task_t *task);
void scheduler_dequeue(task_t *task);

void resched_current(void);

#endif
