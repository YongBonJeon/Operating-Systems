#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
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
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/off_t.h"



static void syscall_handler (struct intr_frame *);

struct lock file_lock;

void
syscall_init (void) 
{
    lock_init(&file_lock);
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
        check_user_vaddr(f->esp + 8);
        check_user_vaddr(f->esp + 12);
        f->eax = read((int)*(uint32_t *)(f->esp + 4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*((uint32_t *)(f->esp + 12)));
        break;
    case SYS_WRITE:
        check_user_vaddr(f->esp + 4);
        check_user_vaddr(f->esp + 12);
        f->eax = write((int)*(uint32_t *)(f->esp + 4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*((uint32_t *)(f->esp + 12)));
        break;
    case SYS_FIBO:
        check_user_vaddr(f->esp + 4);
        f->eax = fibonacci((int)*(uint32_t *)(f->esp + 4));
        break;
    case SYS_MAX:
        check_user_vaddr(f->esp + 4);
        check_user_vaddr(f->esp + 8);
        check_user_vaddr(f->esp + 12);
        check_user_vaddr(f->esp + 16);
        f->eax = max_of_four_int((int)*(uint32_t *)(f->esp + 4), (int)*(uint32_t *)(f->esp + 8), (int)*(uint32_t *)(f->esp + 12), (int)*(uint32_t *)(f->esp + 16));
        break;
    case SYS_CREATE:
        check_user_vaddr(f->esp + 4);
        check_user_vaddr(f->esp + 8);
        f->eax = create((const char *)*(uint32_t *)(f->esp+4), (unsigned)*((uint32_t *)(f->esp + 8)));
        break;
    case SYS_REMOVE:
        check_user_vaddr(f->esp + 4);
        f->eax = remove((const char *)*(uint32_t *)(f->esp+4));
        break;
    case SYS_OPEN:
        check_user_vaddr(f->esp + 4);
        f->eax = open((const char *)*(uint32_t *)(f->esp+4));
        break;
    case SYS_FILESIZE:
        check_user_vaddr(f->esp + 4);
        f->eax = filesize((int)*(uint32_t *)(f->esp+4));
        break;
    case SYS_SEEK:
        check_user_vaddr(f->esp + 4);
        check_user_vaddr(f->esp + 8);
        seek((int)*(uint32_t *)(f->esp+4), (unsigned)*(uint32_t *)(f->esp+8));
        break;
    case SYS_TELL:
        check_user_vaddr(f->esp + 4);
        f->eax = tell((int)*(uint32_t *)(f->esp+4));
        break;
    case SYS_CLOSE:
        check_user_vaddr(f->esp + 4);
        close((int)*(uint32_t *)(f->esp+4));
        break;
    }
}

void halt(void){
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

    for(int i=3; i<128; i++){
		if((cur->file_descriptor)[i] != NULL){
			close(i);
		}
	}

    file_close(thread_current()->cur_file);
    
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

int read(int fd, void *buffer, unsigned size){
    check_user_vaddr(buffer);
    lock_acquire(&file_lock);
    int result = -1;

    if(fd == STDIN_FILENO){
        int i;
        for(i = 0 ; i < (int)size ; i++){
            ((char *)buffer)[i] = input_getc();
            if(((char *)buffer)[i] == '\0')
                break;
        }
        result = i;
    }
    else{
        if((thread_current()->file_descriptor)[fd] == NULL){
            lock_release(&file_lock);
            exit(-1);
        }
        result = file_read((thread_current()->file_descriptor)[fd], buffer, size);
    }
    lock_release(&file_lock);
    return result;
}

int write (int fd, const void *buffer, unsigned size) {
    check_user_vaddr(buffer);
    lock_acquire(&file_lock);
    int result = -1;

    if (fd == STDOUT_FILENO) {
        putbuf((char *)buffer, size);
        result = size;
    }
    else{
        if((thread_current()->file_descriptor)[fd] == NULL){
            lock_release(&file_lock);
            exit(-1);
        }
        if((thread_current()->file_descriptor)[fd]->deny_write){
            file_deny_write((thread_current()->file_descriptor)[fd]);
        }
        result =  file_write((thread_current()->file_descriptor)[fd], buffer, size);
    }
    lock_release(&file_lock);
    return result; 
}

bool create(const char *file, unsigned initial_size){
    if(file == NULL)
        exit(-1);
    return filesys_create(file, initial_size);
}

bool remove(const char *file){
    if(file == NULL)
        exit(-1);
    return filesys_remove(file);
}

int open(const char *file){
    if(file == NULL)
        exit(-1);
    lock_acquire(&file_lock);
    struct file* fp = filesys_open(file);
    int result = -1;
    if(fp != NULL){
        if(strcmp(thread_current()->name, file) == 0){
                    file_deny_write(fp);
        }
        //* open file and insert file to file_descriptor */
        for(int i = 3 ; i < 128 ; i++){
            if(thread_current()->file_descriptor[i] == NULL){
                /* running executable thread can't modified */
                thread_current()->file_descriptor[i] = fp;
                result = i;
                break;
            }
        }
    }
    lock_release(&file_lock);
    return result;
}

int filesize(int fd){
    if(thread_current()->file_descriptor[fd] == NULL)
        exit(-1);
    return file_length(thread_current()->file_descriptor[fd]);
}

void seek(int fd, unsigned position){
    if(thread_current()->file_descriptor[fd] == NULL)
        exit(-1);
    file_seek(thread_current()->file_descriptor[fd], position);
}

unsigned tell(int fd){
    if(thread_current()->file_descriptor[fd] == NULL)
        exit(-1);
    return file_tell(thread_current()->file_descriptor[fd]);
}

void close(int fd){
    if(thread_current()->file_descriptor[fd] == NULL)
        exit(-1);
    
    file_close(thread_current()->file_descriptor[fd]);
    thread_current()->file_descriptor[fd] = NULL;
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
    if(!pagedir_get_page(thread_current()->pagedir, vaddr))
		exit(-1);
 }
