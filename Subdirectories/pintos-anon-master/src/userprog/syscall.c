
#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "pagedir.h"
#include <string.h>
#include "debug.h"

static void syscall_handler (struct intr_frame *);

void syscall_halt(void);
void syscall_exit(struct intr_frame *);
void syscall_exec(struct intr_frame *);
void syscall_wait(struct intr_frame *);
void syscall_create(struct intr_frame *);
void syscall_remove(struct intr_frame *);
void syscall_open(struct intr_frame *);
void syscall_filesize(struct intr_frame *);
void syscall_read(struct intr_frame *);
void syscall_write(struct intr_frame *);
void syscall_seek(struct intr_frame *);
void syscall_tell(struct intr_frame *);
void syscall_close(struct intr_frame *);

void halt(void);
void exit(int);
pid_t exec(const char*);
int wait(pid_t pid);
bool create(const char*,unsigned);
bool remove(const char*);
int open(const char*);
int filesize(int fd);
int read(int,void *,unsigned);
int write(int,const void *,unsigned);
void seek(int,unsigned);
unsigned tell(int);
void close(int);

struct fd* find_fd_by_num(int);
bool pointer_valid(void *,int);
void close_all_fd(void);


int fd_num = 2;       
/* file descriptor */
struct fd{
    int num;
    struct file *file;
    struct list_elem elem;
};
struct list file_list;

struct fd*
find_fd_by_num(int num)
{
  struct list_elem *e;
  struct thread *cur = thread_current();
  for (e = list_begin (&cur->fd_list); e != list_end (&cur->fd_list); e = e->prev)
  {
    struct fd *fd = list_entry (e, struct fd, elem);
    if(fd->num == num)return fd;
  }
  return NULL;
}

bool
pointer_valid(void* esp,int num)
{
  int i;
  struct thread *cur = thread_current();
  for(i=0;i<num*4;i++)
  {
    if(!is_user_vaddr(esp+i) || pagedir_get_page(cur->pagedir,esp+i) == NULL)
    {
      return false;
    }
  }
  return true;
}

bool 
char_pointer_valid(char *pointer)
{
  if(pointer == NULL || !pointer_valid(pointer,1))
  {
    return false;
  }
  return true;
}

void
close_all_fd()
{
  struct list_elem *e;
  struct thread *cur = thread_current ();
  while (!list_empty(&cur->fd_list))
  {
    e = list_begin(&cur->fd_list);
    close(list_entry(e, struct fd, elem)->num);
  }
  file_close(cur->execfile);
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init(&file_list);
  lock_init(&file_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{
  if(!pointer_valid(f->esp,1))
  {
    exit(-1);
  }
  int *p = f->esp;
  if(p == NULL)
  {
    exit(-1);
  }
  switch (*p)
  {
  case SYS_HALT:
    syscall_halt();
    break;
  case SYS_EXIT:
    syscall_exit(f);
    break;
  case SYS_EXEC:
    syscall_exec(f);
    break;
  case SYS_WAIT:
    syscall_wait(f);
    break;
  case SYS_CREATE:
    syscall_create(f);
    break;
  case SYS_REMOVE:
    syscall_remove(f);
    break;
  case SYS_OPEN:
    syscall_open(f);
    break;
  case SYS_FILESIZE:
    syscall_filesize(f);
    break;  
  case SYS_READ:
    syscall_read(f);
    break;
  case SYS_WRITE:
    syscall_write(f);
    break;
  case SYS_SEEK:
    syscall_seek(f);
    break;
  case SYS_TELL:
    syscall_tell(f);
    break;
  case SYS_CLOSE:
    syscall_close(f);
    break;
  default:
    exit(-1);
    break;
  }
}

void 
syscall_halt(void)
{
  halt();
}

void 
halt(void)
{
  shutdown_power_off();
}

void 
syscall_exit(struct intr_frame *f)
{
  if(!pointer_valid(f->esp+4,1))
  {
    exit(-1);
  }
  int status = *(int*)(f->esp+4);
  exit(status);
}

void
exit(int status)
{
  close_all_fd();
  thread_current()->ret = status;
  thread_exit();
}

void 
syscall_exec(struct intr_frame *f)
{
  if(!pointer_valid(f->esp+4,1))
  {
    exit(-1);
  }
  char *cmd_line = *(char**)(f->esp+4);
  if(!char_pointer_valid(cmd_line))
  {
    exit(-1);
  }
  f->eax = exec(cmd_line);
}


pid_t
exec(const char* cmd_line)
{
  return process_execute(cmd_line);
}

void 
syscall_wait(struct intr_frame *f)
{
   if(!pointer_valid(f->esp+4,1))
  {
    exit(-1);
  }
  pid_t pid = *(int*)(f->esp+4);
  f->eax = wait(pid);
}

int 
wait(pid_t pid)
{
  return process_wait(pid);
}

void 
syscall_create(struct intr_frame *f)
{
  if(!pointer_valid(f->esp+4,2))
  {
    exit(-1);
  }
  char *file = *(char**)(f->esp+4);
  if(!char_pointer_valid(file))
  {
    exit(-1);
  }
  unsigned initial_size = *(int *)(f->esp+8);
  lock_acquire(&file_lock);
  f->eax = create(file,initial_size);
  lock_release(&file_lock);
}

bool 
create(const char*file , unsigned initial_size)
{
  return filesys_create(file,initial_size);
}

void
syscall_remove(struct intr_frame *f)
{
   if(!pointer_valid(f->esp+4,1))
  {
    exit(-1);
  }
  char *file = *(char**)(f->esp+4);
  if(!char_pointer_valid(file))
  {
    exit(-1);
  }
  lock_acquire(&file_lock);
  f->eax = remove(file);
  lock_release(&file_lock);
}

bool 
remove(const char* file)
{
  return filesys_remove(file);
}

void 
syscall_open(struct intr_frame *f)
{
   if(!pointer_valid(f->esp+4,1))
  {
    exit(-1);
  }
  char *file = *(char**)(f->esp+4);
  if(!char_pointer_valid(file))
  {
    exit(-1);
  }
  lock_acquire(&file_lock);
  f->eax = open(file);
  lock_release(&file_lock);
}

int 
open(const char* file)
{
  struct file *f = filesys_open(file);
  if(f == NULL)
  {
    return -1;                                
  }
  struct fd *fd = malloc(sizeof(struct fd));
  if(fd == NULL)
  {
    file_close(f);
    return -1;
  }
  struct thread *cur = thread_current();
  fd->file = f;                                        
  fd->num = fd_num;                                        
  fd_num++;
  list_push_back(&cur->fd_list,&fd->elem);
  return fd->num;
}

void
syscall_filesize(struct intr_frame *f)
{
   if(!pointer_valid(f->esp+4,1))
  {
    exit(-1);
  }
  int fd = *(int*)(f->esp+4);
  lock_acquire(&file_lock);
  f->eax = filesize(fd);
  lock_release(&file_lock);
}

int 
filesize(int fd)
{
  struct fd *f = find_fd_by_num(fd);
  if(f == NULL)
  {
    return -1;
  }
  return file_length(f->file);
}

void 
syscall_read(struct intr_frame *f)
{
  if(!pointer_valid(f->esp+4,3))
  {
    exit(-1);
  }
  int fd = *(int*)(f->esp+4);
  void *buffer = *(char**)(f->esp+8);
  unsigned size = *(unsigned*)(f->esp+12);
  if(!char_pointer_valid(buffer))
  {
    exit(-1);
  }
  lock_acquire(&file_lock);
  f->eax = read(fd,buffer,size);
  lock_release(&file_lock);
}

int 
read(int fd,void *buffer,unsigned size)
{
  if(fd == 0)
  {
    int i;
    for(i=0;i<size;i++){
      (*((char**)buffer))[i] = input_getc();
    }
    return size;
  }
  struct fd* f = find_fd_by_num(fd);
  if(f == NULL)
  {
    return -1;                                        
  }
  return file_read(f->file,buffer,size);
}

void 
syscall_write(struct intr_frame *f)
{
   if(!pointer_valid(f->esp+4,3))
  {
    exit(-1);
  }
  int fd = *(int*)(f->esp+4);
  void *buffer = *(char**)(f->esp+8);
  unsigned size = *(unsigned*)(f->esp+12);
  if(!char_pointer_valid(buffer))
  {
    exit(-1);
  }
  lock_acquire(&file_lock);
  f->eax = write(fd,buffer,size);
  lock_release(&file_lock);
}

int 
write(int fd,const void* buffer,unsigned size)
{
  if(fd == 1)
  {
    int i;
    putbuf(buffer,size);
    return size;
  }
  struct fd* f = find_fd_by_num(fd);
  if(f == NULL)
  {
    return -1;
  }
  return file_write(f->file,buffer,size); 
}

void
syscall_seek(struct intr_frame *f)
{
   if(!pointer_valid(f->esp+4,2))
  {
    exit(-1);
  }
  int fd = *(int*)(f->esp+4);
  unsigned position = *(unsigned*)(f->esp+8);
  seek(fd,position);
}

void
seek(int fd, unsigned position)
{
  struct fd *f = find_fd_by_num(fd);
  if(f == NULL)
  {
    exit(-1);
  }
  lock_acquire(&file_lock);
  file_seek(f->file,position);
  lock_release(&file_lock); 
}

void
syscall_tell(struct intr_frame *f)
{
  if(!pointer_valid(f->esp+4,1))
  {
    exit(-1);
  }
  int td = *(int*)(f->esp+4);
  lock_acquire(&file_lock);
  f->eax = tell(td);
  lock_release(&file_lock);
}

unsigned
tell(int fd)
{
  struct fd *f = find_fd_by_num(fd);
  if(f == NULL)
  {
    return -1;
  }
  return file_tell(f->file);
}

void
syscall_close(struct intr_frame *f)
{
  if(!pointer_valid(f->esp+4,1))
  {
    exit(-1);
  }
  int fd = *(int*)(f->esp+4);
  lock_acquire(&file_lock);
  close(fd);
  lock_release(&file_lock);
}

void
close(int fd)
{
  struct fd *f = find_fd_by_num(fd);
  if(f == NULL)
  {
    return -1;
  }
  file_close(f->file);
  list_remove(&f->elem);
  free(f);
}

bool chdir(const char* dir);
bool mkdir(const char* dir);
bool readdir(int fd, char *name);
bool isdir(int fd);
int inumber(int fd);
/*
  Changes the current working directory of the process to dir, which may be 
  relative or absolute. Returns true if successful, false on failure. 
*/
bool chdir(const char* dir) { 
  if (!dir || strlen(dir) == 0)
  {
    return false;
  }
  if(!thread_current()->curr_dir
   || (dir_get_inode(thread_current()->curr_dir)) == ROOT_DIR_SECTOR){
    if(!strcmp(dir, "/") || !strcmp(dir, "..") || !strcmp(dir, ".")){
      return false;
    }
  }
  struct dir *directory = handle_rel_abs_dir(dir);
  if(!directory){
    return false;
  }
  dir_close(thread_current()->curr_dir);
  thread_current()->curr_dir = directory;
  return true;
}

/*
  Creates the directory named dir, which may be relative or absolute. 
  Returns true if successful, false on failure. Fails if dir already exists 
  or if any directory name in dir, besides the last, does not already exist. 
  That is, mkdir("/a/b/c") succeeds only if "/a/b" already exists and 
  "/a/b/c" does not. 
*/
bool mkdir(const char* dir) {
  if(strlen(dir) == 0){
    return false;
  }
  struct dir *target = handle_rel_abs_dir(dir);
  if(target){
    // Directory exists
    dir_close(target);
    return false;
  }
  dir_close(target);
  // Check that the previous directory exists
  int index = strlen(dir) - 1;
  while(index >= 0 && dir[index] != '/'){
    index--;
  }
  index++;
  // Create the directory in root or thread's current directory
  if(index == 1 || index == 0){
    block_sector_t new_dir = 0;
    if(!free_map_allocate (1, &new_dir)
     || !dir_create(new_dir, DIR_CREATE_CNST)){
      return false;
    }
    char *name = index == 1 ? dir + 1 : dir;
    if(index == 0 && thread_current()->curr_dir != NULL){
      if(!dir_add(thread_current()->curr_dir, name, new_dir)){
        return false;
      }
      struct inode *inode = NULL;
      if(!dir_lookup(thread_current()->curr_dir, name, &inode)){
        inode_close(inode);
        return false;
      }
      struct dir *child = dir_open(inode);
      if(!dir_add(child, ".", new_dir) || !dir_add(child, "..", 
        inode_get_inumber(dir_get_inode(thread_current()->curr_dir)))){
           dir_close(child);
           return false;
      }
      dir_close(child);
    }else{
      if(!dir_add(dir_open_root(), name, new_dir)){
        return false;
      }
      struct inode *inode = NULL;
      if(!dir_lookup(dir_open_root(), name, &inode)){
        inode_close(inode);
        return false;
      }
      struct dir *child = dir_open(inode);
      if(!dir_add(child, ".", new_dir)
       || !dir_add(child, "..", ROOT_DIR_SECTOR)){
           dir_close(child);
           return false;
      }
      dir_close(child);
    }
    return true;
  }
  
  char *prev_name = calloc(1, strlen(dir) + 1);
  strlcpy(prev_name, dir, index);
  target = handle_rel_abs_dir(prev_name);
  free(prev_name);
  if(!target){
    // Directory does not exist
    return false;
  }
  // Allocate into target
  block_sector_t new_dir = 0;
  if(!free_map_allocate (1, &new_dir)
   || !dir_create(new_dir, DIR_CREATE_CNST)){
    return false;
  }
  if(!dir_add(target, dir + index, new_dir)){
    return false;
  }
      struct inode *inode = NULL;
      if(!dir_lookup(target, dir + index, &inode)){
        inode_close(inode);
        return false;
      }
      struct dir *child = dir_open(inode);  
      if(!dir_add(child, ".", new_dir)
       || !dir_add(child, "..", inode_get_inumber(dir_get_inode(target)))){
           dir_close(child);
           return false;
      }
  dir_close(child);
  return true;
}
/*
  Reads a directory entry from file descriptor fd, which must represent 
  a directory. If successful, stores the null-terminated file name in name, 
  which must have room for READDIR_MAX_LEN + 1 bytes, and returns true. 
  If no entries are left in the directory, returns false.

  "." and ".." should not be returned by readdir.

  If the directory changes while it is open, then it is acceptable for some 
  entries not to be read at all or to be read multiple times. Otherwise, each 
  directory entry should be read once, in any order.

  READDIR_MAX_LEN is defined in "lib/user/syscall.h". If your file system 
  supports longer file names than the basic file system, you should increase 
  this value from the default of 14.
*/
bool readdir(int fd, char *name) {
  struct file * curr_file = thread_current()->fd_list[fd];
   // Error checking
  if(curr_file == NULL){
    return false;
  }

  struct dir * curr_dir = (struct dir *) curr_file;
  struct inode *curr_inode = dir_get_inode(curr_dir);
  // Error checking
  if(curr_inode == NULL){
    return false;
  }
  // Need to check if is subdir
  bool sub_d = inode_is_subdir(curr_inode);
  if(!sub_d){
    return false;
  }

  bool continue_readdir = dir_readdir(curr_dir, name);
  // Special cases "." directory, and ".." directory.
  while(continue_readdir == true){
    if((strcmp(name, ".") != 0) && strcmp(name, "..") != 0){
      break;
    }
    else{
      continue_readdir =  dir_readdir(curr_dir, name);
    }
  }
  return continue_readdir;
}

/*  
  Returns true if fd represents a directory, false if 
  it represents an ordinary file. 
*/
bool isdir(int fd) {
  struct file * curr_file = thread_current()->fd_list[fd];
  // Error checking
  if(curr_file == NULL){
    return -1;
  }
  struct inode * inode = file_get_inode(curr_file);
  bool is_dir = inode_is_subdir(inode);
  return is_dir;
}

/*
  Returns the inode number of the inode associated with fd, which may 
  represent an ordinary file or a directory.

  An inode number persistently identifies a file or directory. It is 
  unique during the file's existence. In Pintos, the sector number of 
  the inode is suitable for use as an inode number.
*/
int inumber(int fd) {
  struct file * curr_file = thread_current()->fd_list[fd];
  // Error checking
  if(curr_file == NULL){
    return -1;
  }
  struct inode * inode = file_get_inode(curr_file);
  // Error checking
  int inum = -1;
  if(inode == NULL){
    return inum;
  }
  else{
    inum =  inode_get_inumber(inode);
    return inum;
  }
}
