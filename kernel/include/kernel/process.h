#ifndef PROCESS_H
#define PROCESS_H

#include <stdint.h>
#include <stdbool.h>
#include <kernel/paging.h>

#define MAX_PROCESSES 256
#define TASK_NAME_MAX 32
#define KERNEL_STACK_SIZE 8192

typedef enum {
    TASK_RUNNING = 0,
    TASK_INTERRUPTIBLE,
    TASK_UNINTERRUPTIBLE,
    TASK_ZOMBIE,
    TASK_DEAD,
} task_state_t;

typedef enum {
    SCHED_NORMAL = 0,
    SCHED_FIFO,
    SCHED_RR,
    SCHED_BATCH,
    SCHED_IDLE,
} sched_policy_t;

struct cpu_context {
    uint32_t eax, ebx, ecx, edx;
    uint32_t esi, edi;
    uint32_t ebp, esp;
    uint32_t eip, eflags;
    // NOTE: CR3 removed - always loaded from task->mm->physical_addr to avoid sync issues
    uint16_t cs, ds, ss, es, fs, gs;
} __attribute__((packed));

struct sched_stats {
    uint64_t exec_start;
    uint64_t sum_exec_runtime;
    uint64_t nvcsw;
    uint64_t nivcsw;
};

struct task_struct {
    volatile int state;
    int pid;
    char name[TASK_NAME_MAX];

    int policy;
    int priority;
    int time_slice;
    int time_remaining;
    struct sched_stats stats;

    struct cpu_context context;

    address_space_t *mm;
    void *kernel_stack;

    struct task_struct *parent;
    int exit_code;

    struct task_struct *next;
    struct task_struct *prev;
};

typedef struct task_struct task_t;

void process_init(void);
task_t* process_create(const char *name, void (*entry_point)(void), int priority);
void process_destroy(task_t *task);
task_t* process_current(void);
void process_set_current(task_t *task);
void process_exit(int exit_code) __attribute__((noreturn));
void process_yield(void);
void process_print_all(void);
task_t* process_get_by_pid(int pid);

void idle_task(void);

#endif
