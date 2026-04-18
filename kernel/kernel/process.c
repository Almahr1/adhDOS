#include <kernel/memory.h>
#include <kernel/paging.h>
#include <kernel/process.h>
#include <kernel/sched.h>
#include <stdio.h>
#include <string.h>

task_t *process_table[MAX_PROCESSES];
extern task_t *current_task = NULL;
task_t *idle_process = NULL;
static int next_pid = 1;

void reaper_task(void);

void idle_task(void) {
  while (1) {
    asm volatile("hlt");
  }
}

void process_init(void) {
  memset(process_table, 0, sizeof(process_table));
  current_task = NULL;
  next_pid = 1;

  idle_process = process_create("idle", idle_task, IDLE_PRIORITY);
  if (!idle_process) {
    printf("FATAL: Failed to create idle process\n");
    for (;;)
      asm volatile("hlt");
  }

  task_t *reaper = process_create("reaper", reaper_task, 10);
  if (!reaper){
    printf("WARNING: Failed to create reaper task");
  }

  current_task = idle_process;
}

task_t *process_create(const char *name, void (*entry_point)(void),
                       int priority) {
  if (next_pid >= MAX_PROCESSES) {
    return NULL;
  }

  task_t *task = (task_t *)kmalloc(sizeof(task_t));
  if (!task) {
    return NULL;
  }

  memset(task, 0, sizeof(task_t));

  task->pid = next_pid++;
  strncpy(task->name, name, TASK_NAME_MAX - 1);
  task->name[TASK_NAME_MAX - 1] = '\0';

  task->state = TASK_RUNNING;
  task->policy = SCHED_NORMAL;
  task->priority = priority;
  task->time_slice = DEFAULT_TIME_SLICE;
  task->time_remaining = task->time_slice;

  task->kernel_stack = kmalloc(KERNEL_STACK_SIZE);
  if (!task->kernel_stack) {
    kfree(task);
    return NULL;
  }

  task->mm = paging_create_address_space();
  if (!task->mm) {
    kfree(task->kernel_stack);
    kfree(task);
    return NULL;
  }

  // Set up the initial context on the stack
  // The interrupt stub pops from Low -> High Address:
  // 1. DS, 2. POPA (EDI...EAX), 3. Int/Err (discarded), 4. IRET (EIP, CS, EFLAGS)
  uint32_t *stack =
      (uint32_t *)((char *)task->kernel_stack + KERNEL_STACK_SIZE);

  // 1. IRET Frame
  stack--;
  *stack = 0x202; // EFLAGS (Interrupts Enabled, Reserved bit 1 set)
  stack--;
  *stack = 0x08;  // CS (Kernel Code Segment)
  stack--;
  *stack = (uint32_t)entry_point; // EIP (Entry Point)

  // 2. Interrupt cleanup (popped by "add $8, %esp")
  stack--;
  *stack = 0; // Error Code
  stack--;
  *stack = 0; // Interrupt Number

  // 3. General Purpose Registers (POPA)
  stack--;
  *stack = 0; // EAX
  stack--;
  *stack = 0; // ECX
  stack--;
  *stack = 0; // EDX
  stack--;
  *stack = 0; // EBX
  stack--;
  *stack = 0; // ESP (Ignored)
  stack--;
  *stack = 0; // EBP
  stack--;
  *stack = 0; // ESI
  stack--;
  *stack = 0; // EDI

  // 4. Segment Registers (Popped First)
  stack--;
  *stack = 0x10; // DS (Kernel Data Segment)

  task->context.esp = (uint32_t)stack;

  // Context fields initialized for safety/logging
  task->context.ebp = 0;
  task->context.eip = (uint32_t)entry_point;
  task->context.eflags = 0x202;
  task->context.cs = 0x08;
  task->context.ds = 0x10;

  for (int i = 0; i < MAX_PROCESSES; i++) {
    if (process_table[i] == NULL) {
      process_table[i] = task;
      break;
    }
  }

  scheduler_enqueue(task);

  return task;
}

void process_destroy(task_t *task) {
  if (!task)
    return;

  for (int i = 0; i < MAX_PROCESSES; i++) {
    if (process_table[i] == task) {
      process_table[i] = NULL;
      break;
    }
  }

  if (task->mm) {
    paging_destroy_address_space(task->mm);
  }
  if (task->kernel_stack) {
    kfree(task->kernel_stack);
  }
  kfree(task);
}

task_t *process_current(void) { return current_task; }

void process_set_current(task_t *task) { current_task = task; }

void process_exit(int exit_code) {
  task_t *current = process_current();
  current->exit_code = exit_code;
  current->state = TASK_ZOMBIE;

  scheduler_dequeue(current);

  printf("Process %d (%s) exiting with code %d\n", current->pid, current->name,
         exit_code);

  schedule();
  
  process_yield(); 

  for (;;)
    ;
}

void process_yield(void) {
  asm volatile("int $0x80");
}

void process_print_all(void) {
  printf("\n=== Process Table ===\n");
  printf("PID\tName\t\tState\tPriority\n");

  for (int i = 0; i < MAX_PROCESSES; i++) {
    task_t *task = process_table[i];
    if (task) {
      const char *state_str;
      switch (task->state) {
      case TASK_RUNNING:
        state_str = "RUN";
        break;
      case TASK_INTERRUPTIBLE:
        state_str = "SLEEP";
        break;
      case TASK_UNINTERRUPTIBLE:
        state_str = "USLEEP";
        break;
      case TASK_ZOMBIE:
        state_str = "ZOMBIE"; 
        break;
      case TASK_DEAD:
        state_str = "DEAD";
        break;
      default:
        state_str = "UNKNOWN";
        break;
      }

      printf("%d\t%s\t\t%s\t%d\n", task->pid, task->name, state_str, task->priority);
    }
  }
  printf("=====================\n\n");
}

task_t *process_get_by_pid(int pid) {
  for (int i = 0; i < MAX_PROCESSES; i++) {
    if (process_table[i] && process_table[i]->pid == pid) {
      return process_table[i];
    }
  }
  return NULL;
}

// Reaper.... Awww Man!
void reaper_task(void) {
  bool reaped_any = false;
  while (1) {
    for (int i = 0; i < MAX_PROCESSES; i++){
      task_t *task = process_table[i];
      if (task != NULL && task->state == TASK_ZOMBIE){

        printf("Reaper: Killing Task (%d)", task->pid);

        if (task->mm){
          paging_destroy_address_space(task->mm);
        }
        if (task->kernel_stack){
          kfree(task->kernel_stack);
        }

        kfree(task);
        process_table[i] = NULL;
        reaped_any = true;
      }
    }
  }
  if (!reaped_any){
    process_yield();
  }
}