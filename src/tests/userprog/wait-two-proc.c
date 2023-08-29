/* Test whether or not the OS can correctly wait for a process to complete on one child, get the return code, then wait for an entirely different process to complete on a seperate child. In essence, tests whether or not the wait syscall finishes without compromising any functionality of the OS after it is finished.  */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  pid_t child1 = exec("child-simple");
  pid_t child2 = exec("child-simple");
  msg("wait(exec()) = %d", wait(child1));
  msg("wait(exec()) = %d", wait(child2));
}