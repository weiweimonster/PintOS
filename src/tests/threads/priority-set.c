/* Verifies that the new priority a thread's priority is set to is valid  */

#include <stdio.h>
#include "tests/threads/tests.h"
#include "threads/init.h"
#include "threads/thread.h"

static thread_func changing_thread;

void test_priority_set(void) {
  /* This test does not work with the MLFQS. */
  ASSERT(active_sched_policy == SCHED_PRIO);

  msg("Setting thread priority below priority minimum.");
  thread_set_priority(PRI_MIN - 10);
  msg("Thread should have priority %d.  Actual priority: %d.", PRI_MIN, thread_get_priority()); 

  msg("Setting thread priority above priority maximum."); 
  thread_set_priority(PRI_MAX + 10);
  msg("Thread should have priority %d.  Actual priority: %d.", PRI_MAX, thread_get_priority()); 

  msg("Thread should have just exited.");
}
