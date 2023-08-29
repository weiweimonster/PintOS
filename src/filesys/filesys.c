#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/process.h"

/* Partition that contains the file system. */
struct block* fs_device;

static void do_format(void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");
  for (int i = 0; i < 64; i++) {
    cache[i] = malloc(sizeof(cache_block));
    cache[i]->valid = false;
    cache[i]->index = i;
    lock_init(&cache[i]->cache_lock);
  }
  list_init(&LRU_list);
  lock_init(&LRU_lock);
  inode_init();
  free_map_init();
  
  
  if (format)
    do_format();

  free_map_open();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) {
  lock_acquire(&LRU_lock);
  struct list_elem* e;
  for (e = list_begin(&LRU_list); e != list_end(&LRU_list); e = list_next(e)) {
    cache_block* cache_entry = list_entry(e, cache_block, elem);
    lock_acquire(&cache_entry->cache_lock);
    if (cache_entry->dirty) {
      block_write(fs_device, cache_entry->tag, cache_entry->data);
      cache_entry->dirty = false;
    }
    lock_release(&cache_entry->cache_lock);
  }
  lock_release(&LRU_lock);
for (int i = 0; i < 64; i++) {
  free(cache[i]);
}
  free_map_close(); 
}

bool filesys_dir_create(const char* name, struct dir* parent) {

    block_sector_t sector;
    free_map_allocate(1, &sector);
    bool success = dir_create(sector, 16);
    if (!success) {
      free_map_release(sector, 1);
      return false;
    }

    if(dir_add(parent, name, sector)) {
      struct dir* newDir = dir_open(inode_open(sector));
      dir_add(newDir, "..", inode_get_inumber(dir_get_inode(parent)));
      dir_add(newDir, ".", sector);
      dir_close(newDir);
      return true;
    } else {
      free_map_release(sector, 1);
      return false;
    }
    
    
    
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char* name, off_t initial_size, struct dir* cwd) {
  block_sector_t inode_sector = 0;
  struct dir* dir = cwd ? dir_reopen(cwd) : dir_open_root();
  bool success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
                  inode_create(inode_sector, initial_size, false) && dir_add(dir, name, inode_sector));
  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  dir_close(dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file* filesys_open(const char* name) {
  struct thread* t = thread_current();
  struct dir* dir = t->pcb->cwd ? dir_reopen(t->pcb->cwd) : dir_open_root();
  struct inode* inode = NULL;

  if (dir != NULL)
    dir_lookup(dir, name, &inode);
  dir_close(dir);

  return file_open(inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* name) {
  struct dir* dir = dir_open_root();
  bool success = dir != NULL && dir_remove(dir, name);
  dir_close(dir);

  return success;
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16))
    PANIC("root directory creation failed");

  struct dir *root = dir_open_root();
  dir_add(root, "..", ROOT_DIR_SECTOR);
  dir_add(root, ".", ROOT_DIR_SECTOR);
  dir_close(root);
  free_map_close();
  printf("done.\n");
}
