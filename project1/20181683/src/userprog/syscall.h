#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

typedef int pid_t;

void syscall_init (void);

/* Project 1 */
void halt(void);
void exit(int status);
pid_t exec (const char *cmd_line);
int wait (pid_t pid);
int write (int fd, const void *buffer, unsigned size);
int read (int fd, const void *buffer, unsigned size);

/* Project 1 additional */
int fibonacci(int n);
int max_of_four_int(int a, int b, int c, int d);

void check_user_vaddr(const void *vaddr);

#endif /* userprog/syscall.h */
