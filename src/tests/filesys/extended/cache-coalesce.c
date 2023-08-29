/* This test checks the buffer cache’s ability to coalesce writes to the same sector. 
Each block device keeps a read_cnt counter and a write_cnt counter. 
Write a large large file at least 64 KiB (i.e. twice the maximum allowed buffer cache size) byte-by-byte. 
Then, read it in byte-by-byte. 
The total number of device writes should be on the order of 128 since 64 KiB is 128 blocks. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"
#include "tests/filesys/seq-test.h"
#include <random.h>

static char buf[65536];
static char other_buf[65536];

void test_main(void) {
  const char* file_name = "testfile";
  size_t size = 65536;
  size_t initial_size = 0;
  size_t ofs;
  int fd;
  
  random_bytes(buf, size);
  CHECK(create(file_name, initial_size), "create \"%s\"", file_name);
  CHECK((fd = open(file_name)) > 1, "open \"%s\"", file_name);

  ofs = 0;
  //Write file byte by byte
  msg("writing \"%s\"", file_name);
  while (ofs < size) {
    if (write(fd, buf + ofs, 1) != 1)
      fail("write %zu bytes at offset %zu in \"%s\" failed",1, ofs, file_name);

    ofs += 1;
  }
  msg("close \"%s\"", file_name);
  close(fd);

  // Read file, byte by byte
  random_bytes(other_buf, size);
  CHECK((fd = open(file_name)) > 1, "open \"%s\"", file_name);
  ofs = 0;

  msg("reading \"%s\"", file_name);
  while (ofs < size) {
    if (read(fd, other_buf + ofs, 1) != 1)
      fail("read %zu bytes at offset %zu in \"%s\" failed", 1, ofs, file_name);

    ofs += 1;
  }
  
  //Check total # of device writes should be on the order of 128. 
  int num_writes = get_device_writes();
  ASSERT(num_writes > 0);
  ASSERT(num_writes < 2000);
  //Close file, conclude test
  
  msg("close \"%s\"", file_name);
  close(fd);
  
}
