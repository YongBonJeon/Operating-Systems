#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/vaddr.h"
#include "process.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "pagedir.h"
#include "exception.h"

static void syscall_handler (struct intr_frame *);
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* -main에서 system call 호출 
    -lib/user/syscall.c 에서 interrupt 0x30 
    -vector table에서 (자동으로) syscall_handler 호출
    -f->esp에 system call number 저장되어 있음
*/
static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  uint32_t syscall_num = *(uint32_t *)f->esp;

  switch(syscall_num){
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      check_user_vaddr(f->esp + 4);
      exit((int)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_EXEC:
      check_user_vaddr(f->esp + 4); 
      f->eax = (uint32_t)exec((const char*)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_WAIT:
      check_user_vaddr(f->esp + 4);
      f->eax = wait((uint32_t)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_READ:
      check_user_vaddr(f->esp + 4);
      f->eax = read((int)*(uint32_t *)(f->esp + 4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*((uint32_t *)(f->esp + 12)));
      break;
    case SYS_WRITE:
      check_user_vaddr(f->esp + 4);
      f->eax = write((int)*(uint32_t *)(f->esp + 4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*((uint32_t *)(f->esp + 12)));
      break;
    case SYS_FIBO:
      check_user_vaddr(f->esp + 4);
      f->eax = fibonacci((int)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_MAX:
      check_user_vaddr(f->esp + 4);
      f->eax = max_of_four_int((int)*(uint32_t *)(f->esp + 4), (int)*(uint32_t *)(f->esp + 8), (int)*(uint32_t *)(f->esp + 12), (int)*(uint32_t *)(f->esp + 16));
      break;
  }
}

void halt(){
  /* shutdown PintOS */
  shutdown_power_off();
}

void exit(int status){
  /* get running thread struct */
  struct thread* cur = thread_current();
  /* store child exit status */
  cur->child_exit_status = status;
  /* print process termination message */
  printf("%s: exit(%d)\n", cur->name, status);
  /* thread exit */
  thread_exit (); // 내부에서 process_exit() 호출 
}

pid_t exec (const char *cmd_line)
{
	return process_execute(cmd_line);
}

int wait (pid_t pid)
{
  return process_wait ((tid_t) pid);
}

int read(int fd, const void *buffer, unsigned size){
  if(fd == STDIN_FILENO){
    int i;
    for(i = 0 ; i < (int)size ; i++){
      ((char *)buffer)[i] = input_getc();
      if(((char *)buffer)[i] == '\0')
        break;
    }
    if(i != (int)size)
      return -1;
    else
      return size;
  }
  return -1;
}

int write (int fd, const void *buffer, unsigned size) {
  if (fd == STDOUT_FILENO) {
    putbuf((char *)buffer, size);
    return size;
  }
  return -1; 
}

int fibonacci(int n){
  if(n < 0){
    return -1;
  }
  int *fibo = (int*)malloc(sizeof(int)*n);
  fibo[0] = 0; fibo[1] = 1; 
  for(int i = 2 ; i <= n ; i++){
    fibo[i] = fibo[i-1] + fibo[i-2];
  }
  return fibo[n];
}

int max_of_four_int(int a, int b, int c, int d){
  int max = b;
  if(max < a)
    max = b;
  if(max < c)
    max = c;
  if(max < d)
    max = d;
  return max;
}

void check_user_vaddr(const void *vaddr) {
	if(!vaddr)
		exit(-1);
	if(!is_user_vaddr(vaddr))
		exit(-1);
 }
