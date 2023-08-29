/* Removes a newly created file. Open should fail. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  CHECK(create("newfile.txt", 0), "create \"newfile.txt\"");
  CHECK(remove("newfile.txt"), "remove \"newfile.txt\"");
  int handle = open("newfile.txt");
  if (handle != -1)
    fail("open() returned %d", handle);
}
