#include <unistd.h>
#include <sched.h>
#include <syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <errno.h>

#define CLONE_CAGE 0x02000000

static int clone_function(void *argv){
	char **arg = *((char ***)argv);
	execvp(*(arg+1), arg+1);
	return 0;
}


int main(int argc, char *argv[]){

	char * stack;
	int size = 65536;
	int status;
	pid_t pid;
	int err;
	stack = malloc(size);
	clone(clone_function, stack+size, CLONE_CAGE, &argv);	
	pid = waitpid(-1, &status, __WCLONE);
	return 0;
}
