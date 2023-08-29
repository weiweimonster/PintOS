#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

#include "threads/synch.h"
/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define DOUBLE_INDIRECT_BLOCKS 16384
#define INDIRECT_BLOCKS 128
#define DIRECT_BLOCKS 123

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  block_sector_t direct[DIRECT_BLOCKS];
  block_sector_t indirect;
  block_sector_t doubly_indirect;
  off_t length;         /* File size in bytes. */
  int isdir;            /* Determines if inode is a directory */
  unsigned magic;       /* Magic number. */
};



/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

/* In-memory inode. */
struct inode {
  struct lock inode_lock; /* lock for this inode */
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
  // struct inode_disk data; /* Inode content. */
  bool isDir;
};

int hits = 0, misses = 0;

void cache_miss (block_sector_t sector_idx, void* buffer, int rw) {
  misses++;
  // the cache is full so we have to evict a cache entry
  lock_acquire(&LRU_lock);
  int size = list_size(&LRU_list);
  lock_release(&LRU_lock);
  if (size == 64) {
    lock_acquire(&LRU_lock);
    struct list_elem *e = list_pop_front(&LRU_list);
    cache_block* cache_entry = list_entry(e, cache_block, elem);
    list_push_back(&LRU_list, e);
    lock_release(&LRU_lock);
    lock_acquire(&cache_entry->cache_lock);
    if (cache_entry-> dirty) {
      block_write(fs_device, cache_entry->tag, cache_entry->data);
    }
    cache_entry->tag = sector_idx;
    cache_entry->dirty = false;
    block_read(fs_device, sector_idx, cache_entry->data);
    // read from cache to buffer
    if (rw == 0) {
      memcpy(buffer, cache_entry->data, BLOCK_SECTOR_SIZE);
    } else {
      // write from buffer to cache
      cache_entry->dirty = true;
      memcpy(cache_entry->data, buffer, BLOCK_SECTOR_SIZE);
    }
    lock_release(&cache_entry->cache_lock);
  } else {
    int i = 0;
    bool found = false;
    for (; i < 64; i++) {
      if (!cache[i]->valid) {
        lock_acquire(&cache[i]->cache_lock);
        if (!cache[i]->valid) {
          cache[i]->valid = true;
          found = true;
        }
        lock_release(&cache[i]->cache_lock);
        if (found) break;
      }
    }
    cache_block* cache_entry = cache[i];
    cache_entry->tag = sector_idx;
    cache_entry->dirty = false;
    lock_acquire(&LRU_lock);
    list_push_back(&LRU_list, &cache_entry->elem);
    lock_release(&LRU_lock);
    lock_acquire(&cache_entry->cache_lock);
    block_read(fs_device, sector_idx, cache_entry->data);
    if (rw == 0) {
      memcpy(buffer, cache_entry->data, BLOCK_SECTOR_SIZE);
    } else {
      cache_entry->dirty = true;
      memcpy(cache_entry->data, buffer, BLOCK_SECTOR_SIZE);
    }
    lock_release(&cache_entry->cache_lock);
  }
}

void cache_read(block_sector_t sector_idx, void* buffer) {
  bool hit = false;
  for (int i = 0; i < 64; i++) {
    // check the tag of the valid cache entries
    if (cache[i]->valid && cache[i]->tag == sector_idx) {
      lock_acquire(&cache[i]->cache_lock);
      // cache hit
      if (cache[i]->tag == sector_idx) {
        lock_acquire(&LRU_lock);
        list_remove(&cache[i]->elem);
        list_push_back(&LRU_list, &cache[i]->elem);
        lock_release(&LRU_lock);
        memcpy(buffer, cache[i]->data, BLOCK_SECTOR_SIZE);
        hit = true;
        hits++;
      } 
      lock_release(&cache[i]->cache_lock);
      if (hit) return;
    } 
  }
  cache_miss(sector_idx, buffer, 0);
}

void cache_write(block_sector_t sector_idx, void* buffer) {
  bool hit = false;
  for (int i = 0; i < 64; i++) {
    if (cache[i]->valid && cache[i]->tag == sector_idx) {
      lock_acquire(&cache[i]->cache_lock);
      // cache hit
      if (cache[i]->valid && cache[i]->tag == sector_idx) {
        lock_acquire(&LRU_lock);
        list_remove(&cache[i]->elem);
        list_push_back(&LRU_list, &cache[i]->elem);
        lock_release(&LRU_lock);
        cache[i]->dirty = true;
        hit = true;
        memcpy(cache[i]->data, buffer, BLOCK_SECTOR_SIZE);
      }
      lock_release(&cache[i]->cache_lock);
      if (hit) return;
    }
  }
  cache_miss(sector_idx, buffer, 1);
}
/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
  bool hold_lock = false;
  if (!lock_held_by_current_thread(&inode->inode_lock)) {
    lock_acquire(&inode->inode_lock);
    hold_lock = true;
  }
  /* Read in the inode from disk. */
  struct inode_disk disk_inode;
  cache_read(inode->sector, &disk_inode);

  /* Calculate the block # from the offset pos */
  int block = pos / BLOCK_SECTOR_SIZE;
  if (pos < disk_inode.length) {
    if (block < DIRECT_BLOCKS) {
      /* Find the inumber of the direct block where pos lands */
      if (hold_lock) {
        lock_release(&inode->inode_lock);
        hold_lock = false;
      }
      return disk_inode.direct[pos / BLOCK_SECTOR_SIZE];
    } else if ( block - DIRECT_BLOCKS < INDIRECT_BLOCKS) {
      /* Find the inumber of the indirect block where pos lands */

      block_sector_t* indirect = calloc(sizeof(block_sector_t), 128);
      cache_read(disk_inode.indirect, indirect);
      block_sector_t retval = indirect[block - DIRECT_BLOCKS];
      free(indirect);
      if (hold_lock) {
        lock_release(&inode->inode_lock);
        hold_lock = false;
      }
      return retval;
    } else {
      /* Find the inumber of the doubly-indirect block where pos lands */

      /* First read in the doubly-indirect block */
      block_sector_t* doubly_indirect = calloc(sizeof(block_sector_t), 128);
      cache_read(disk_inode.doubly_indirect, doubly_indirect);
      block -= (DIRECT_BLOCKS + INDIRECT_BLOCKS);

      /* Then read in the indirect block */
      block_sector_t* indirect = calloc(sizeof(block_sector_t), 128);
      cache_read(doubly_indirect[block/128], indirect);
      block_sector_t retval = indirect[block % 128];

      free(doubly_indirect);
      free(indirect);
      if (hold_lock) {
        lock_release(&inode->inode_lock);
        hold_lock = false;
      }
      return retval;
    }
  }
  if (hold_lock) {
        lock_release(&inode->inode_lock);
      }
  return -1;

}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;
static struct lock open_inodes_lock;
/* Initializes the inode module. */
void inode_init(void) { 
  list_init(&open_inodes); 
  lock_init(&open_inodes_lock);
  }

bool inode_is_dir(struct inode *inode) {
  lock_acquire(&inode->inode_lock);
  bool retval = inode->isDir;
  lock_release(&inode->inode_lock);
  return retval;
}

int inode_get_open_cnt(struct inode *inode) {
  lock_acquire(&inode->inode_lock);
  int retval = inode->open_cnt;
  lock_release(&inode->inode_lock);
  return retval;
}

/* This function allocates SIZE sectors within the doubly_indirect block.
 * If the doubly_indirect block already exists, it will continue allocating
 * where it left off from START. Otherwise it will allocate the doubly_indirect block as well.*/
bool allocate_doubly_indirect (block_sector_t* doubly_indirect, size_t size, size_t start) {
  bool success;
  int i = 0;
  block_sector_t* buf = calloc(sizeof(block_sector_t), 128);
  size_t offset = start % 128;
  if (*doubly_indirect == 0) {
    success = free_map_allocate(1, doubly_indirect);
    if (!success) {
      *doubly_indirect = 0;
      return false;
  }
  } else {
    
    cache_read(*doubly_indirect, buf);
    i = start / 128;
    size_t indirect_size = size < (128 - offset) ? size : (128 - offset);
    success = allocate_indirect(&buf[i], indirect_size);
    if (!success) {
      return false;
    }
    size -= indirect_size;
    i++;
  }
  int j = i;
  for (; i < 128 && size > 0; i++, size -= 128) {
    if (size < 128) {
      success = allocate_indirect(&buf[i], size);
      size = 128;
    } else {
      success = allocate_indirect(&buf[i], 128);
      // success = free_map_allocate(1, &buf[i]);
    }
    if (!success) {
      if (j - 1 >= 0) {
        block_sector_t* indirect_buf = calloc(sizeof(block_sector_t), 128);
        cache_read(buf[j-1], indirect_buf);
        for(; offset < 128; offset++) {
          free_map_release(indirect_buf[offset], 1);
          indirect_buf[offset] = 0;
        }
        cache_write(buf[j-1], indirect_buf);
        free(indirect_buf);
      }
      for (; j < i; j++) {
        free_indirect(buf[j]);
        buf[j] = 0;
      }
      free_map_release(*doubly_indirect, 1);
      return false;
    }
  }
  if (size > 0) {
    for (int j = 0; j < 128; j++) {
      free_indirect(buf[j]);
      buf[j] = 0;
    }
    free_map_release(*doubly_indirect, 1);
  }
  cache_write(*doubly_indirect, buf);
  free(buf);
  return true;
}

/* This function allocates SIZE sectors within the indirect block.
 * If the indirect block already exists, it will continue allocating
 * where it left off. Otherwise it will allocate the indirect block as well.*/
bool allocate_indirect(block_sector_t* indirect, size_t size) {
  bool success;
  int i = 0;
  int j = 0;
  block_sector_t* buf = calloc(sizeof(block_sector_t), 128);
  if (*indirect == 0) {
    success = free_map_allocate(1, indirect);  
    if (!success) {
      *indirect = 0;
      free(buf);
      return false;
    }
  } else {
    cache_read(*indirect, buf);
    for (; i < 128; i++) {
      if (buf[i] == 0) {
        j = i;
        break;
      }
    }
  }
  static char zeros[BLOCK_SECTOR_SIZE];
  size += i;
  for (; i < size; i++) {
    success = free_map_allocate(1, &buf[i]);
    if (!success) {
      for (; j < i; j++) {
        free_map_release(buf[j], 1);
        buf[j] = 0;
      }
      cache_write(*indirect, buf);
      free_map_release(*indirect, 1);
      free(buf);
      return false;
    }
    cache_write(buf[i], zeros);
  }
  cache_write(*indirect, buf);
  free(buf);
  return true;
}

/* This function frees a doubly indirect block and all direct and indirect blocks
 * within the doubly indirect block. */
void free_doubly_indirect(block_sector_t sector_idx) {
  block_sector_t* doubly_indirect = calloc(sizeof(block_sector_t), 128);
  cache_read(sector_idx, doubly_indirect);
  for (int i = 0; i < 128; i++) {
    if (doubly_indirect[i] != 0){
      free_indirect(doubly_indirect[i]);
      doubly_indirect[i] = 0;
    }
  }
  cache_write(sector_idx, doubly_indirect);
  free_map_release(sector_idx, 1);
  free(doubly_indirect);
}

/* This function frees an indirect block and all direct blocks within. */
void free_indirect(block_sector_t sector_idx) {
  block_sector_t* buf = calloc(sizeof(block_sector_t), 128);
  cache_read(sector_idx, buf);
  for (int i = 0; i < 128; i++) {
    if (buf[i] != 0) {
      free_map_release(buf[i], 1);
      buf[i] = 0;
    }
  }
  cache_write(sector_idx, buf);
  free(buf);
  free_map_release(sector_idx, 1);
}

/* This function allocates all the sectors needed for an inode. */
bool inode_disk_init(size_t num_sectors, struct inode_disk* disk_inode) {

  bool indirect_allocated = false;
  bool doubly_indirect_allocated = false;
  size_t num_sectors_allocated = 0;
  size_t blocks_allocated = 0;
  bool success = false;
  static char zeros[BLOCK_SECTOR_SIZE];

  /* Check if num_sectors exceeds max file size. */
  if (num_sectors > (DOUBLE_INDIRECT_BLOCKS + INDIRECT_BLOCKS + DIRECT_BLOCKS)) {
    return false;
  }
  
  /* First allocate as many direct blocks as possible. */
  while (num_sectors > 0 && num_sectors_allocated < DIRECT_BLOCKS) {
    success = free_map_allocate(1, &disk_inode->direct[num_sectors_allocated]);
    if (!success) {
      
      /* Upon failure, return to starting state. */
      for (int i = 0; i < num_sectors_allocated; i++) {
        free_map_release(disk_inode->direct[i], 1);
        disk_inode->direct[i] = 0;
      }
      return false;
    } 
    cache_write(disk_inode->direct[num_sectors_allocated], zeros);
    num_sectors_allocated++;
    num_sectors--;
}
  if (num_sectors > 0) {
    /* Next allocate as much of the indirect space as possible. */
    size_t size = num_sectors < INDIRECT_BLOCKS ? num_sectors : INDIRECT_BLOCKS;
    indirect_allocated = allocate_indirect(&disk_inode->indirect, size); 
    if (!indirect_allocated) {
      for (int i = 0; i < num_sectors_allocated; i++) {
          free_map_release(disk_inode->direct[i], 1);
          disk_inode->direct[i] = 0;
      }
      return false;
    }
    num_sectors -= size;
  }
  if (num_sectors > 0 && !doubly_indirect_allocated) {
    /* Finally allocate as much of the doubly indirect space as possible. */
    size_t size = num_sectors < DOUBLE_INDIRECT_BLOCKS ? num_sectors : DOUBLE_INDIRECT_BLOCKS;
    doubly_indirect_allocated = allocate_doubly_indirect(&disk_inode->doubly_indirect, size, 0); 
    if (!doubly_indirect_allocated) {
      free_indirect(disk_inode->indirect);
      disk_inode->indirect = 0;
      for (int i = 0; i < num_sectors_allocated; i++) {
        free_map_release(disk_inode->direct[i], 1);
        disk_inode->direct[i] = 0;
      }
      return false;
    }
    num_sectors -= size;
  } 
  return true;
}
/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length, bool isdir) {
  struct inode_disk* disk_inode = NULL;
  bool success = false;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof *disk_inode);
  if (disk_inode != NULL) {
    size_t sectors = bytes_to_sectors(length);
    disk_inode->length = length;
    disk_inode->magic = INODE_MAGIC;
    disk_inode->isdir = isdir;

    /* Allocate all the space needed for the inode. */
    if (inode_disk_init(sectors, disk_inode)) {
      cache_write(sector, disk_inode);
      success = true;
    }
    free(disk_inode);
  }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
  struct list_elem* e;
  struct inode* inode;

  /* Check whether this inode is already open. */
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      inode_reopen(inode);
      return inode;
    }
  }

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front(&open_inodes, &inode->elem);
  lock_init(&inode->inode_lock);
  lock_acquire(&inode->inode_lock);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;

  // block_read(fs_device, inode->sector, &inode->data);
  struct inode_disk* buf = malloc(BLOCK_SECTOR_SIZE);
  cache_read(inode->sector, buf);
  inode->isDir = buf->isdir;
  free(buf);
  lock_release(&inode->inode_lock);
  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  if (inode != NULL) {
    inode->open_cnt++;
  }

  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode* inode) { return inode->sector; }

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode* inode) {
  /* Ignore null pointer. */
  if (inode == NULL)
    return;
  lock_acquire(&inode->inode_lock);
  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0) {
    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);

    /* Deallocate blocks if removed. */
    if (inode->removed) {
      struct inode_disk disk_inode;
      cache_read(inode->sector, &disk_inode);
      for (int i = 0; i < DIRECT_BLOCKS; i++) {
        if (disk_inode.direct[i] != 0) {
          free_map_release(disk_inode.direct[i], 1);
          disk_inode.direct[i] = 0;
        }
      }
      if(disk_inode.indirect) free_indirect(disk_inode.indirect);
      disk_inode.indirect = 0;
      if(disk_inode.doubly_indirect) free_doubly_indirect(disk_inode.doubly_indirect);
      disk_inode.doubly_indirect = 0;
      cache_write(inode->sector, &disk_inode);
      free_map_release(inode->sector, 1);
      // free_map_release(inode->data.start, bytes_to_sectors(inode->data.length));
    }
    lock_release(&inode->inode_lock);
    free(inode);
    inode= NULL;
  }
  if (inode) lock_release(&inode->inode_lock);
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
  ASSERT(inode != NULL);
  lock_acquire(&inode->inode_lock);
  inode->removed = true;
  lock_release(&inode->inode_lock);
}

/* This function resizes an inode to accommadate enough space
 * to write SIZE bytes starting at OFFSET. */
bool resize(struct inode* inode, size_t size, off_t offset) {
  size_t sectors_need = bytes_to_sectors(size + offset - inode_length(inode));
  if (size + offset - inode_length(inode) < BLOCK_SECTOR_SIZE) {
    if(bytes_to_sectors(inode_length(inode))*BLOCK_SECTOR_SIZE - inode_length(inode) > size + offset - inode_length(inode)) {
      sectors_need = 0;
    }
  }
  size_t start_sector_idx = bytes_to_sectors(inode_length(inode));
  size_t start = start_sector_idx;
  struct inode_disk disk_inode;

  /* If sectors_need is greater than the max file size, fail. */
  if (sectors_need > DIRECT_BLOCKS+INDIRECT_BLOCKS+DOUBLE_INDIRECT_BLOCKS-start_sector_idx) {
    return false;
  }
  bool success;
  static char zeros[512] = {0};
  cache_read(inode->sector, &disk_inode);
  while (start_sector_idx < DIRECT_BLOCKS && sectors_need > 0) {
    /* First allocate as many direct blocks as possible. */
    success = free_map_allocate(1, &disk_inode.direct[start_sector_idx]);
    cache_write(disk_inode.direct[start_sector_idx], zeros);
    if (!success) {
      for (int i = start; i < start_sector_idx; i++) {
        free_map_release(disk_inode.direct[i], 1);
        disk_inode.direct[i] = 0;
      }
      cache_write(inode->sector, &disk_inode);
      return false;
    }
    start_sector_idx++;
    sectors_need--;
  }
  if (start_sector_idx < (INDIRECT_BLOCKS + DIRECT_BLOCKS) && sectors_need > 0) {
    /* Allocate as many indirect blocks as possible. */
    size_t indirect_size = sectors_need < (DIRECT_BLOCKS + INDIRECT_BLOCKS - start_sector_idx) 
                              ? sectors_need : (DIRECT_BLOCKS + INDIRECT_BLOCKS - start_sector_idx);
    success = allocate_indirect(&disk_inode.indirect, indirect_size);
    if (!success) {
      for (int i = start; i < start_sector_idx; i++) {
        free_map_release(disk_inode.direct[i], 1);
        disk_inode.direct[i] = 0;
      }
      cache_write(inode->sector, &disk_inode);
      return false;
    }
    start_sector_idx += indirect_size;
    sectors_need -= indirect_size;
  } 
  if (start_sector_idx < (INDIRECT_BLOCKS + DIRECT_BLOCKS + DOUBLE_INDIRECT_BLOCKS) && sectors_need > 0) {
    /* Allocate as many doubly-indirect blocks as possible. */
    size_t doubly_indirect_size = sectors_need < (DIRECT_BLOCKS + INDIRECT_BLOCKS + DOUBLE_INDIRECT_BLOCKS - start_sector_idx)
                  ? sectors_need : (DIRECT_BLOCKS + INDIRECT_BLOCKS - start_sector_idx);
    success = allocate_doubly_indirect(&disk_inode.doubly_indirect, doubly_indirect_size, start_sector_idx - DIRECT_BLOCKS - INDIRECT_BLOCKS);
    if (!success) {
      int i = start;
      for (; i < DIRECT_BLOCKS; i++) {
        free_map_release(disk_inode.direct[i], 1);
        disk_inode.direct[i] = 0;
      }
      block_sector_t* buf = malloc(sizeof(block_sector_t) * 128);
      cache_read(disk_inode.indirect, buf);
      for(;i < DIRECT_BLOCKS + INDIRECT_BLOCKS; i++) {
        free_map_release(buf[i - DIRECT_BLOCKS], 1);
        buf[i - DIRECT_BLOCKS] = 0;
      }
      cache_write(disk_inode.indirect, buf);
      cache_write(inode->sector, &disk_inode);
      free(buf);
      return false;
    }
    start_sector_idx += doubly_indirect_size;
    sectors_need -= doubly_indirect_size;
  }
  disk_inode.length = disk_inode.length < (offset + size) ? (offset + size) : disk_inode.length;
  cache_write(inode->sector, &disk_inode);   
  return true;
}
/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t* bounce = NULL;
  lock_acquire(&inode->inode_lock);
  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Read full sector directly into caller's buffer. */
      // block_read(fs_device, sector_idx, buffer + bytes_read);
      cache_read(sector_idx, buffer + bytes_read);
    } else {
      /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }
      // block_read(fs_device, sector_idx, bounce);
      cache_read(sector_idx, bounce);
      memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }
  free(bounce);
  lock_release(&inode->inode_lock);
  return bytes_read;
}
 

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t* bounce = NULL;
  lock_acquire(&inode->inode_lock);
  //if(inode_get_inumber(inode) != FREE_MAP_SECTOR && inode_length(inode) < size + offset) {
  if(inode_length(inode) < size + offset) {
    if (!resize(inode, size, offset)) {
      lock_release(&inode->inode_lock);
      return 0;
    }
  }

  if (inode->deny_write_cnt) {
    lock_release(&inode->inode_lock);
    return 0;
  }

  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    //if (inode_get_inumber(inode) == FREE_MAP_SECTOR) sector_idx = 0;
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Write full sector directly to disk. */
      // block_write(fs_device, sector_idx, buffer + bytes_written);
      cache_write(sector_idx, buffer + bytes_written);
    } else {
      /* We need a bounce buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }

      /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
      if (sector_ofs > 0 || chunk_size < sector_left)
        // block_read(fs_device, sector_idx, bounce);
        cache_read(sector_idx, bounce);
      else 
        memset(bounce, 0, BLOCK_SECTOR_SIZE);

      memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
      // block_write(fs_device, sector_idx, bounce);
      cache_write(sector_idx, bounce);
      
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }
  free(bounce);
  lock_release(&inode->inode_lock);
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {
  lock_acquire(&inode->inode_lock);
  inode->deny_write_cnt++;
  lock_release(&inode->inode_lock);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  lock_acquire(&inode->inode_lock);
  inode->deny_write_cnt--;
  lock_release(&inode->inode_lock);
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode* inode) { 
  struct inode_disk disk_inode;
  bool hold_lock = false;
  if(!lock_held_by_current_thread(&inode->inode_lock)) {
    lock_acquire(&inode->inode_lock);
    hold_lock = true;
  }
  cache_read(inode->sector, &disk_inode);
  if (hold_lock) {
    lock_release(&inode->inode_lock);
  }
  return disk_inode.length; 
}
