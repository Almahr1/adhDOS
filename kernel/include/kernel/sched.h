#ifndef SCHED_H
#define SCHED_H

#include <kernel/process.h>
#include <stdbool.h>

#define DEFAULT_TIME_SLICE   10
#define IDLE_PRIORITY        255

#define NUM_QUEUES           3
#define MLFQ_BOOST_INTERVAL  1000

extern const int queue_slices[NUM_QUEUES];

void scheduler_init(void);
void scheduler_tick(void);
void schedule(bool voluntary);

task_t* scheduler_pick_next(void);
void scheduler_enqueue(task_t *task);
void scheduler_dequeue(task_t *task);

void resched_current(void);

#endif
