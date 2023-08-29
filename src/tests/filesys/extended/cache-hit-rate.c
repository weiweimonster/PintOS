/* Tests the cache effectiveness by measuring the hit rate 
   when a file is opened the first time and again when it is
   closed, then opened a second time. */

#include <syscall.h>
#include "tests/userprog/sample.inc"
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
    int fd; 
    create("test", 0);
    fd = open("test");

    size_t size = 1024;
    size_t block_size = 512;
    size_t ret_val;
    size_t ofs = 0;
    // while (ofs < size) {
    //     char block[512];
    //     size_t block_size, ret_val;

    //     block_size = size - ofs;
    //     if (block_size > sizeof block)
    //         block_size = sizeof block;

    //     ret_val = read(fd, block, block_size);
    //     // if (ret_val != block_size)
    //     //     fail("read of %zu bytes at offset %zu in sample.txt returned %zu", block_size, ofs, ret_val);
    //     msg("retval: %d\n, block: %s", ret_val, block);
    //     ofs += block_size;
    // }
    
    char buf[size];
    //random_bytes(buf, size);
    ret_val = write(fd, buf, 512);
    //msg("retval: %d,\n buf: %s", ret_val, buf);
    
    // Get hit rate
    int hits1 = get_hits();
    int misses1 = get_misses();
    float hit_rate1 = (float) hits1 / (float) (hits1 + misses1);
    //msg("Hit rate 1: %f", hit_rate1);
    close(fd);
    
    fd = open("test");
    
    size = sample;
    block_size = 512;
    ofs = 0;
    while (ofs < size) {
        char block[512];
        size_t block_size, ret_val;

        block_size = size - ofs;
        if (block_size > sizeof block)
            block_size = sizeof block;

        ret_val = read(fd, block, block_size);
        // if (ret_val != block_size)
        //     fail("read of %zu bytes at offset %zu in sample.txt returned %zu", block_size, ofs, ret_val);
        ofs += block_size;
    }

    // Get hit rate again
    int hits2 = get_hits() - hits1;
    int misses2 = get_misses() - misses1;
    float hit_rate2 = (float) hits2 / (float) (hits2 + misses2);
    //msg("Hit rate 2: %f", hit_rate2);

    CHECK(hit_rate1 < hit_rate2, "Hit rate 1 must be less than hit rate 2");
}
