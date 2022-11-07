/* addtional.c

    Print the result of 'fibonacci' system call using [num 1] as parameter
    Print the result of 'max_of_four_int' system call using [num 1, 2, 3, 4] as parameter

*/

#include <stdio.h>
#include <syscall.h>
#include <stdlib.h>

int
main (int argc, char *argv[])
{
  if(argc != 5){
    return EXIT_FAILURE;
  }
  
  printf("%d ",fibonacci(atoi(argv[1])));
  printf("%d\n",max_of_four_int(atoi(argv[1]), atoi(argv[2]), atoi(argv[3]), atoi(argv[4])));

  return EXIT_SUCCESS;
}
