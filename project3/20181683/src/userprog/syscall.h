#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include "filesys/off_t.h"

typedef int pid_t;
/* An open file. */
struct file 
  {
    struct inode *inode;        /* File's inode. */
    off_t pos;                  /* Current position. */
    bool deny_write;            /* Has file_deny_write() been called? */
  };

void syscall_init (void);

/* Project 1 */
void halt(void);
void exit(int status);
pid_t exec (const char *cmd_line);
int wait (pid_t pid);
int write (int fd, const void *buffer, unsigned size);
int read (int fd, void *buffer, unsigned size);

/* Project 1 additional */
int fibonacci(int n);
int max_of_four_int(int a, int b, int c, int d);

/* Project 2 */
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);


void check_user_vaddr(const void *vaddr);

#endif /* userprog/syscall.h */
