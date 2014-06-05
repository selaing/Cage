#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>

#define sys_chmem 314

	
int main(int argc, char *argv[]){
	char option;
	unsigned long pid;
	unsigned long address;
	unsigned long label;
	int selection;
	long ret;

	while((option = getopt(argc, argv, "c:u:l:")) != -1)
	switch(option){
		case 'c':
			pid = atol(optarg);
			address = strtoul(argv[optind], NULL, 16);
			label = strtoul(argv[optind+1], NULL, 16);
			selection = 0;
			break;
		case 'u':
			pid = atol(optarg);
			address = strtoul(argv[optind], NULL, 16);
			label = 0;
			selection = 1;
			break;
		case 'l':
			pid = atol(optarg);
			address = strtoul(argv[optind], NULL, 16);
			label = strtoul(argv[optind+1], NULL, 16);
			selection = 0;
			break;
		default:
			break;
	}

	
	kill(pid,0);
	if(errno == ESRCH){
		printf("ERROR: Invalid PID\n");
		return 0;
	}

	
	ret = syscall(sys_chmem, selection, pid, address, label);
	if(ret != 0){
		printf("ERROR: %d", ret);
	}
	return 0; 
}
