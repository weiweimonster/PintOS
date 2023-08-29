#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "devices/shutdown.h"

//Proj1 filesys addition
#include "filesys/off_t.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/thread.h"

#include "lib/float.h"
// Proj3 addition
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "string.h"
#include "devices/block.h"

struct dir;
extern bool filesys_dir_create(const char*, struct dir *);

static void syscall_handler(struct intr_frame*);
void practice(struct intr_frame *, int);
file_entry* fd_to_file_entry(int);

//Filesys syscalls
void sys_write(struct intr_frame*);
void sys_create(struct intr_frame*);
void sys_remove(struct intr_frame*);
int open_file (const char* file_name);
void sys_open(struct intr_frame*);
void sys_read(struct intr_frame*);
void sys_file_size(struct intr_frame*);
void sys_seek(struct intr_frame*);
void sys_tell(struct intr_frame*);
void sys_close(struct intr_frame*);

// Process control syscalls
void halt(void);
void exec(struct intr_frame *, const char *);
void wait(struct intr_frame *, pid_t);

/* Argument validation functions */

bool validate_mem(uint32_t *pd, void *addr, int n); // Validates n bytes starting at addr
void *get_arg(struct intr_frame *, int index); // Gets and validates the next syscall argument at index
bool validate_buf(void *addr); // Validates a buffer pointed to by addr
block_sector_t path_resolution(const char* file_name, char* buf);
static int get_next_part(char part[NAME_MAX + 1], const char** srcp) {
  const char* src = *srcp;
  char* dst = part;

  /* Skip leading slashes.  If it's all slashes, we're done. */
  while (*src == '/')
    src++;
  if (*src == '\0')
    return 0;

  /* Copy up to NAME_MAX character from SRC to DST.  Add null terminator. */
  while (*src != '/' && *src != '\0') {
    if (dst < part + NAME_MAX)
      *dst++ = *src;
    else
      return -1;
    src++;
  }
  *dst = '\0';

  /* Advance source pointer. */
  *srcp = src;
  return 1;
}

block_sector_t path_resolution_target(const char* file_name, char* buf, bool shouldExist) {
  struct thread* t = thread_current();
  char part[NAME_MAX + 1];
  char* pos = file_name;
  struct inode* inode = NULL;
  struct dir* cwd = file_name[0] == '/' ? dir_open_root() : dir_reopen(t->pcb->cwd);
  block_sector_t sector_idx = 0;

  if(strlen(file_name) == 0) return 0;
  
  while (true) {
    if(get_next_part(part, &pos) != 1) {

      // If the entire path is just the root directory
      if (inode_get_inumber(dir_get_inode(cwd)) == ROOT_DIR_SECTOR) {
        inode = NULL;
      }

      break;
    }

    if (buf) strlcpy(buf, part, NAME_MAX + 1);

    if(!dir_lookup(cwd, part, &inode)) {
      if(!shouldExist) {
        inode = dir_get_inode(cwd);
      }
      break;
    }
    
    if (inode_is_dir(inode)) {
      char part_temp[NAME_MAX + 1];
      char *temp = pos;
      if(get_next_part(part_temp, &temp) != 1) {
        inode_close(inode);
        inode = dir_get_inode(cwd);
        if (!shouldExist) inode = NULL;
        break;
      }
      dir_close(cwd);
      cwd = dir_open(inode);
    }
    else {
      inode_close(inode);
      inode = dir_get_inode(cwd);
      if (!shouldExist) inode = NULL;
      break;
    }
  }

  if (inode) {
    sector_idx = inode_get_inumber(inode);
  }
  if (cwd) dir_close(cwd);

  return sector_idx;
}

block_sector_t path_resolution(const char* file_name, char* buf) {
  struct thread* t = thread_current();
  char part[NAME_MAX + 1];
  char* pos = file_name;
  struct inode* inode = NULL;
  struct dir* cwd = file_name[0] == '/' ? dir_open_root() : dir_reopen(t->pcb->cwd);
  struct file* file = NULL;
  block_sector_t sector_idx = 0;

  if(strlen(file_name) == 0) return 0;
  
  while (true) {
    if(get_next_part(part, &pos) != 1) {

      // If the entire path is just the root directory
      if (inode_get_inumber(dir_get_inode(cwd)) == ROOT_DIR_SECTOR)
        inode = dir_get_inode(cwd);

      break;
    }
    if(!dir_lookup(cwd, part, &inode)) {
      if (buf) strlcpy(buf, part, NAME_MAX + 1);
      else inode = NULL;   
      break;
    }
    
    dir_close(cwd);
    cwd = NULL;
    if (inode_is_dir(inode))
      cwd = dir_open(inode);
    else {
      file = file_open(inode);
      break;
    }
  }

  if (buf) {
    if (file) {
      inode = file_get_inode(inode);
    } else {
      inode = dir_get_inode(cwd);
    }
  }
  if (inode) {
    sector_idx = inode_get_inumber(inode);
  }
  if (cwd) dir_close(cwd);
  if (file) {
    file_close(file);
  }
  return sector_idx;
}


void syscall_init(void) { 
  lock_init(&file_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); 
}

void halt() {
  shutdown_power_off();
}

void exec(struct intr_frame *f, const char *cmd_line) {
  f->eax = process_execute(cmd_line);
}

void wait(struct intr_frame *f, pid_t pid) {
  f->eax = process_wait(pid);
}

// write to a file with file descriptor = fd
// use putbuf to output to console if the fd == 1
void sys_write(struct intr_frame* f) {

  // retrieve arguments from the stack
  int fd = (int)get_arg(f, 1);
  const char* buffer =(const char*)get_arg(f, 2);
  //validate the arguments
  if(!validate_buf((void *)buffer)) exit_syscall(f, -1);
  off_t size = (off_t)get_arg(f, 3);
  

  if (fd == 1){ 
    putbuf(buffer, size);
    f->eax = size;
  } else if (fd == 0){
    f->eax = -1;
  }
  else{
    // find the file_entry in the list of map_fd_files
    // return null of the fd is not found in the lists
    file_entry* temp = fd_to_file_entry(fd);
    if (temp == NULL){
      f->eax = -1;
    } else{
      if (temp->isdir) {
        f->eax = -1;
        return;
      }
      struct file* temp_file = (struct file*) fd_to_file_entry(fd)->file;
      //write to the file and return the number of bytes written
      f->eax = file_write(temp_file, buffer, size);
      int i = f->eax;
    }
  }

}


// this function takes in a fd and tries to find the file
// in the map_fd_files with the same fd
// returns the file_entry if found and null otherwise
// Function to search and convert file descriptor to file_entry*
file_entry* fd_to_file_entry(int fd){
  struct list_elem* e;
  struct list* map_list = &(thread_current()->map_fd_files);
  for(e = list_begin(map_list); e != list_end(map_list); e = list_next(e)){
    file_entry* temp = list_entry(e, file_entry, elem);
    if (temp->fd == fd){
      return temp;
    }
  }
  return NULL;
}


// bool remove (const char *file)
// Deletes the file named file. Returns true if successful,
// false otherwise. A file may be removed regardless of whether it 
// is open or closed, and removing an open file does not close it. 
// See this section of the FAQ for more details.

// remove the file from the system with file_name
void sys_remove(struct intr_frame* f){
  //retreive arguments from the stack
  const char* file_name = (const char*)get_arg(f, 1);
  if(!validate_buf((void *)file_name)) exit_syscall(f, -1);
  //sets f->eax to true if the file was removed correctly
  // and false if the file wasn't remove
  
  char part[NAME_MAX + 1];
  block_sector_t sector_idx = path_resolution_target(file_name, part, true);
  struct inode* inode = NULL;
  if (sector_idx != 0)
    inode = inode_open(sector_idx);
  f->eax = false;

  if (inode) {
    struct dir* parent = dir_open(inode);
    struct inode* child;
    dir_lookup(parent, part, &child);
    if(inode_is_dir(child)) {
      if(inode_get_open_cnt(child) == 1) {
        struct dir* child_dir = dir_open(child);
        int entry_count = 0;
        char name[NAME_MAX + 1];
        while(dir_readdir(child_dir, name)) entry_count++;

        if (entry_count == 0) f->eax = dir_remove(parent, part);
        dir_close(child_dir);
      }
    } else {
      inode_close(child);
      f->eax = dir_remove(parent, part);
    }

    dir_close(parent);
  }
  
}

// Disable writing on the file descriptor. Used mainly to prevent running executibles from being written over.
void disable_write(int fd) {
  file_deny_write(fd_to_file_entry(fd)->file);
}

// Attempts to open file_name and creates a file_entry for that file, returning a file descriptor.
int open_file(const char* file_name) {
  struct thread* curr_t = thread_current();
  block_sector_t sector_idx = path_resolution(file_name, NULL);
  struct inode* inode;
  if (sector_idx != 0) {
    inode = inode_open(sector_idx);
  } else {
    inode = NULL;
  }
  void* file = NULL;
  if (inode) {
    if (inode_is_dir(inode)) {
      file = dir_open(inode);
    } else {
      file = file_open(inode);
    }
  }
  
  // struct file* f_open = file_open(inode);
  if (file == NULL){
    return -1;
  } else{
    file_entry* new_file_entry = malloc(sizeof(file_entry));
    if (list_empty(&(curr_t->unused_fd))){
      // assign new fd if there are no elements in unused_fd
      new_file_entry->fd = curr_t->curr_fd;
      curr_t->curr_fd++;
    } else{
      // if there are elements in the unused_fd we use
      // those fd first instead of using new fd. We also 
      // have to free the structure to prevent memory leaks
      struct list_elem* e= list_pop_front(&(curr_t->unused_fd));
      empty_fd* fd_entry = list_entry(e, empty_fd, elem);
      new_file_entry->fd = fd_entry->fd;
      free(fd_entry);
    }
    new_file_entry->file = file;
    new_file_entry->isdir = inode_is_dir(inode);
    list_push_back(&(curr_t->map_fd_files), &(new_file_entry->elem));
    return new_file_entry->fd;
  }
}

// int open (const char *file) returns -1 if file cannot find
// return the fd otherwise

// opened up a file and sets f->eax to the file descriptor 
void sys_open(struct intr_frame* f){
  // retrieve arguments from the stack
  const char* file_name = (const char*)get_arg(f, 1);
  if(!validate_buf((void *)file_name)) exit_syscall(f, -1);
  f->eax = open_file(file_name);
}

void practice(struct intr_frame *f UNUSED, int i) {
  f->eax = ++i;
}

/* Save an approximation of Euler's number 
of n Taylor series terms into register eax */
void compute_e(struct intr_frame *f, int n) {
  f->eax = sys_sum_to_e(n);
}

void exit_syscall(struct intr_frame *f UNUSED, int exitCode) {

  struct process *pcb = thread_current()->pcb;
  
  // Set the process's status so it's parent knows.
  if (exitCode == -1) {
    pcb->info->failed = true;
  } else {
    pcb->info->exited = true;
    pcb->info->retval = exitCode;
  }

  f->eax = exitCode;
  printf("%s: exit(%d)\n", pcb->process_name, exitCode);
  process_exit();
}

bool validate_mem(uint32_t *pd, void *addr, int n) {

  /* validate_mem() checks if addr is not null, is in the user 
     space, and a valid page is returned when calling 
     pagedir_get_page. it performs the same check for addr + n -1.*/

  if(!addr || !is_user_vaddr(addr) || !is_user_vaddr(addr + n - 1)) return false;
  if(!pagedir_get_page(pd, addr)) return false;
  if(!pagedir_get_page(pd, addr + n - 1)) return false;

  return true;
}

void *get_arg(struct intr_frame *f, int index) {

  // Each syscall argument is 4 bytes, so validate the next 4 bytes.
  uint32_t *pd = thread_current()->pcb->pagedir;
  void *addr = f->esp + (index * 4);
  if(validate_mem(pd, addr, 4)) return *(void **)addr;

  // If syscall arguments are invalid, exit(-1)
  exit_syscall(f, -1);

  return NULL;
}

bool validate_buf(void *addr) {

  // Validate byte by byte until a null character is reached.
  if(!validate_mem(thread_current()->pcb->pagedir, addr, 1)) return false;
  while(*(char *)addr != '\0') {

    addr++;
    if (!validate_mem(thread_current()->pcb->pagedir, addr, 1)) {
      return false;
    }
  }
  return true;
}

// creates a new file with name equals to file_name
// sets f->eax = true if successful and false otherwise
void sys_create(struct intr_frame *f){
  struct thread* t = thread_current();
  const char* file_name = (const char*)get_arg(f, 1);
  if(!validate_buf((void *)file_name)) exit_syscall(f, -1);
  if (!file_name || strlen(file_name) > NAME_MAX) {
    f->eax = false;
    return;
  }
  off_t size = (off_t)get_arg(f, 2);
  char buf[NAME_MAX + 1];
  strlcpy(buf, file_name, NAME_MAX + 1);
  block_sector_t sector_idx = path_resolution_target(file_name, buf, false);
  struct inode* inode = NULL;
  if (sector_idx != 0)
    inode = inode_open(sector_idx);

  struct dir* parent = dir_open(inode);
  struct inode* temp;

  f->eax = filesys_create(buf, size, parent);
  dir_close(parent);

}


// reads bytes from the fd and sets f->eax to the actual bytes read
void sys_read(struct intr_frame* f){


  //retrieving arguments from the stack and look it up in the map_fd_files
  int fd = (int)get_arg(f, 1);
  file_entry* temp = fd_to_file_entry(fd);
  if (temp == NULL){
    // returns -1 if the fd is not found in the list
    f->eax = -1;
  } else{
    struct file* file_struct = (struct file*) temp->file;
    const char* buffer = (const char*)get_arg(f, 2);
    // validates the buffer
    if(!validate_buf((void *)buffer)) exit_syscall(f, -1);
    off_t size = (off_t)get_arg(f, 3);
    f->eax = file_read(file_struct, (void*) buffer, size);
  }

}


// int filesize (int fd)
// Returns the size, in bytes, of the open file with file descriptor fd.
void sys_file_size(struct intr_frame* f){


  // retrieving the arguments from the stack
  int fd = (int)get_arg(f, 1);
  file_entry* temp = fd_to_file_entry(fd);
  if (temp == NULL){
    // returns -1 if the fd is not found in the list
    f->eax = -1;
  } else{
    struct file* temp_file = (struct file*) temp->file;
    f->eax = file_length(temp_file);
  }

}


//Changes the next byte to be read or written in open file fd to position, 
//expressed in bytes from the beginning of the file. Thus, a position of 0 is the file’s start.
void sys_seek(struct intr_frame* f){

  int fd = (int)get_arg(f, 1);
  unsigned int position = (unsigned int)get_arg(f, 2);
  file_entry* temp = fd_to_file_entry(fd);
  if (temp == NULL){
    // return -1 if the fd is not found in the list
    f->eax = -1;
  } else{
    struct file* temp_file = (struct file*) fd_to_file_entry(fd)->file;
    file_seek(temp_file, position);
  }

}


// Returns the position of the next byte to be read or written in open file fd, 
// expressed in bytes from the beginning of the file.
void sys_tell(struct intr_frame* f){
\
  int fd = (int)get_arg(f, 1);
  file_entry* temp = fd_to_file_entry(fd);
  if (temp == NULL){
    // returns -1 if the fd is not found in the list
    f->eax = -1;
  } else{
    struct file* temp_file = (struct file*) fd_to_file_entry(fd)->file;
    f->eax = file_tell(temp_file);
  }
}

// Closes file descriptor fd, and free the file_entry in the list map_fd_files to avoid memory leaks
void sys_close(struct intr_frame* f){
  struct thread* curr_t UNUSED = thread_current();
  // retrieve arguments from the stack
  int fd = (int)get_arg(f, 1);
  file_entry* temp_file_entry = fd_to_file_entry(fd);
  if (temp_file_entry != NULL){
    // we have to create a entry to unused_fd to keep track of the fd that are not close
    // so we can reuse thos fd
    empty_fd* closed_fd = malloc(sizeof(empty_fd));
    closed_fd->fd = temp_file_entry->fd;
    list_push_back(&(curr_t->unused_fd), &(closed_fd->elem));
    // if the file is found we close the file and free the file_entry structure that was
    // previously malloced
    if (temp_file_entry->isdir)
      dir_close(temp_file_entry->file);
    else
      file_close(temp_file_entry->file);
    list_remove(&(temp_file_entry->elem));
    free(temp_file_entry);
  } else{
  }
  
}

void sys_inumber(struct intr_frame* f) {
  int fd = (int)get_arg(f, 1);
  file_entry* entry = fd_to_file_entry(fd);
  f->eax = entry->isdir ? inode_get_inumber(dir_get_inode((struct dir*)entry->file)) 
  : inode_get_inumber(file_get_inode((struct file *)entry->file));
}
void sys_chdir(struct intr_frame* f) {
  struct thread* t = thread_current();
  const char* file_name = (const char*)get_arg(f, 1);
  if(!validate_buf((void *)file_name)) exit_syscall(f, -1);
  struct inode* inode = NULL;
  block_sector_t sector_idx = path_resolution(file_name, NULL);
  if (sector_idx != 0)
    inode = inode_open(sector_idx);
  if (inode) {
    dir_close(t->pcb->cwd);
    t->pcb->cwd = dir_open(inode);
    f->eax = true;
  } else {
    f->eax = false;
  }
}

void sys_mkdir(struct intr_frame* f) {
  struct thread *t = thread_current();
  struct dir *cwd = t->pcb->cwd;
  const char* file_name = (const char*)get_arg(f, 1);
  if(!validate_buf((void *)file_name)) exit_syscall(f, -1);
  f->eax = false;
  if(*file_name == '\0') {
    return;
  }
  char part[NAME_MAX + 1];
  block_sector_t sector = path_resolution_target(file_name, part, false);
  if (!sector) return;
  struct dir* dir = dir_open(inode_open(sector));
  f->eax = filesys_dir_create(part, dir);
  dir_close(dir);
}

void sys_rddir(struct intr_frame* f) {
  int fd = (int)get_arg(f, 1); 
  char* name = (char *) get_arg(f, 2);
  if(!validate_buf((void *)name)) exit_syscall(f, -1);
  file_entry* file_entry = fd_to_file_entry(fd);
  if (file_entry->isdir) {
    struct dir* dir = (struct dir*) file_entry->file;
    f->eax = dir_readdir(dir, name);
  } else {
    f->eax = false;
  }
}

void sys_isdir(struct intr_frame* f) {
  int fd = (int)get_arg(f, 1);
  file_entry* file_entry = fd_to_file_entry(fd);
  f->eax = file_entry->isdir;
}

void sys_device_writes(struct intr_frame* f) {
  int num_writes = 0;
  struct block* track_block = block_first();
  while(track_block != NULL){
    num_writes += track_block->write_cnt;
    track_block = block_next(track_block);
  }
  f->eax = num_writes;
}

extern int hits, misses;
void sys_get_hits(struct intr_frame *f) {
  f->eax = hits;
}
void sys_get_misses(struct intr_frame *f) {
  f->eax = misses;
}

static void syscall_handler(struct intr_frame* f UNUSED) {

  int id = (int)get_arg(f, 0);
  
  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */

  switch (id) {

    case SYS_PRACTICE:
      practice(f, (int)get_arg(f, 1)); 
      break; 
    case SYS_EXEC:
      if(!validate_buf((void *)get_arg(f,1))) exit_syscall(f, -1);
      exec(f, (char *)get_arg(f, 1));
      break;
    case SYS_WAIT:
      wait(f, (int)get_arg(f,1));
      break;
    case SYS_WRITE:
      sys_write(f); 
      break;
    case SYS_CREATE:
      sys_create(f);
      break;
    case SYS_REMOVE:
      sys_remove(f);
      break;
    case SYS_OPEN:
      sys_open(f);
      break;
    case SYS_READ:
      sys_read(f);
      break;
    case SYS_FILESIZE:
      sys_file_size(f);
      break;
    case SYS_SEEK:
      sys_seek(f);
      break;
    case SYS_TELL:
      sys_tell(f);
      break;
    case SYS_CLOSE:
      sys_close(f);
      break;
    case SYS_COMPUTE_E:
      compute_e(f, (int)get_arg(f, 1));
      break;
    case SYS_EXIT:
      exit_syscall(f, (int)get_arg(f,1));
      break;
    case SYS_INUMBER:
      sys_inumber(f);
      break;
    case SYS_CHDIR:
      sys_chdir(f);
      break;
    case SYS_MKDIR:
      sys_mkdir(f);
      break;
    case SYS_ISDIR:
      sys_isdir(f);
      break;
    case SYS_READDIR:
      sys_rddir(f);
      break;
    case SYS_GET_HITS:
      sys_get_hits(f);
      break;
    case SYS_GET_MISSES:
      sys_get_misses(f);
      break;
    case SYS_GET_DEVICE_WRITES:
      sys_device_writes(f);
      break;
  }
}
