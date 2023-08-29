#include "threads/interrupt.h"

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);
void exit_syscall(struct intr_frame *, int);
void compute_e(struct intr_frame *f, int n);

int open_file (const char* file_name); // Helper to open file
void disable_write(int); // Helper to disable write on a fd

#endif /* userprog/syscall.h */
