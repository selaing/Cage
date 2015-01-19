#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <sys/wait.h>

#define MAX_QUEUE 5000
#define CAPLENGTH 66
#define PACKED_DATA __attribute__((__packed__))
struct pcap_hdr_s{
        unsigned int magic_number;
        unsigned short version_major;
        unsigned short version_minor;
        int thiszone;
        unsigned int sigfigs;
        unsigned int snaplen;
        unsigned int network;   
};

struct pcaprec_hdr_s{
        unsigned int ts_sec;
        unsigned int ts_usec;
        unsigned int incl_len;
        unsigned int orig_len;
};

typedef struct{
//	struct pcap_pkthdr ph;
	struct pcaprec_hdr_s ph;
	u_char data[66];
}PACKED_DATA packet;

pcap_t *device;
FILE *cap_file;
packet *queue;
packet *queue_head;
packet *queue_tail;
packet *queue_start;
int halting = 0;

void sig_handler(int signo){
	pcap_breakloop(device);
	halting = 1;
}

void enqueue(packet *addr){
	*queue_tail = *addr;
	if(queue_tail < (queue_start + MAX_QUEUE-1)){
		queue_tail++;
		if(queue_tail == queue_head)
			printf("ERROR: Queue Overflow! ");
	}
	else{
		queue_tail = queue_start;
		if(queue_tail == queue_head)
			printf("ERROR: Queue Overflows! ");
	}
	return;	
}

packet *dequeue(void){
	packet *temp;
	if(queue_head != queue_tail){
			temp = queue_head;
		if(queue_head < (queue_start + MAX_QUEUE-1)){
			queue_head++;
			return temp;	
		}
		else{
			queue_head = queue_start;
			return temp;
		}
	}
	return NULL;
}

//void *
static int writeFile(void* x){
	static int count = 0;
	packet *temp;
dequeue:
	//printf("Count = %d\n",count);
	//count++;
	temp = dequeue();
	if(!temp && halting){
		printf("NULL && halting %d\n",count);
		return 0;
	//	return NULL;
	}
	if(!temp)
		goto dequeue;
	//printf("temp and halting %d\n",halting);
	count++;
	fwrite(temp, (sizeof(packet)), 1, cap_file);
	goto dequeue;
	return 0;
//	return NULL;
}

/* Function is called by pcap_dispatch each time a packet is processed
 */
void get_Packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes){
	
	//static int num = 1;
	//printf("Processing Packet %d\n",num);
	//num++;
	
	packet *temp_packet;
	temp_packet = malloc(sizeof(struct pcap_pkthdr)+h->caplen);
	if(!temp_packet){
		printf("Malloc in get_Packet() failed\n");
		return;
	}	
	//temp_packet->ph = *h;
	temp_packet->ph.incl_len = h->caplen;
	temp_packet->ph.orig_len = h->len;
	temp_packet->ph.ts_sec = h->ts.tv_sec;
	temp_packet->ph.ts_usec = h->ts.tv_usec;
	memcpy(&temp_packet->data, bytes, h->caplen);
	enqueue(temp_packet);
	free(temp_packet);
	return;
}

int main(int argc, char *argv[]){
	char errbuf[PCAP_ERRBUF_SIZE];
	int err;
	struct pcap_stat *ps;
	struct pcap_hdr_s header;
	pthread_t writeThread;	
	char *stack;
	int size = 65536;
	int status;

	if(argc != 2){
		printf("\n\tERROR: Must Specify the file in which to write the capture data.\n\tUsage: capture <filename>\n\n");
		return 1;
	}

	if(signal(SIGQUIT, sig_handler) == SIG_ERR){
		printf("Error: Registering signal handler\n");
		return 1;
	}

	cap_file = fopen(argv[1], "w");
	if(!cap_file){
		printf("ERROR: Cannot open file %s\n",argv[1]);
		return 1;
	}

        header.magic_number = 0xa1b2c3d4;
        header.version_major = 2;
        header.version_minor = 4;
        header.thiszone = 0;
        header.sigfigs = 0;
        header.snaplen = 65536;
        header.network = 1;

	err = fwrite(&header, sizeof(struct pcap_hdr_s), 1, cap_file);
	if(err != 1){
		printf("ERROR: Writing pcap header to capture file\n");
		goto fileclose;
	}

	queue = malloc(MAX_QUEUE*sizeof(packet));
	queue_head = queue;
	queue_tail = queue;
	queue_start = queue;
	
	if(!queue){
		printf("ERROR on malloc for queue\n");
		goto fileclose;
	}	

	stack = malloc(size);
	if(!stack){
		printf("ERROR: malloc for child stack\n");
		goto fileclose;
	}

	ps = malloc(sizeof(struct pcap_stat));
	if(!ps){
		printf("ERROR on malloc\n");
		goto fileclose;
	}

	device = pcap_create("me", errbuf);
	if(!device){
		printf("ERROR on pcap_create %s\n",errbuf);
		goto fileclose;
	}
	
	err = pcap_set_promisc(device, 1);
	if(err != 0){
		printf("ERROR on pcap_set_promisc \n");
		goto cleanup;
	}
	err = pcap_set_buffer_size(device, 200*1024*1024);
	if(err != 0){
		printf("ERROR on pcap_set_buffer_size \n");
		goto cleanup;
	}

	err = pcap_activate(device);
	if(err != 0){
		printf("ERROR on pcap_activate \n\t %s\n", pcap_geterr(device));
		goto cleanup;
	}
	
	printf("Capturing off of 'me'...\n");
/*
	if(pthread_create(&writeThread, NULL, writeFile, NULL)){
		printf("ERROR: Creating Writer PThread!\n");
		goto cleanup;
	}
*/
	clone(writeFile, stack+size, CLONE_FILES | CLONE_IO | CLONE_VM, NULL);

	while(!halting){
		err = pcap_dispatch(device, -1, get_Packet, NULL);
		if(err == -1){
			printf("ERROR on pcap_dispatch \n\t %s\n", pcap_geterr(device));
			goto cleanup;
		}
	}


	//printf("size of queue %lx\n", (queue_tail - queue_start));
//	halting = 1;
	//printf("Number of Packets Processed %d\n", err);
/*
	if(pthread_join(writeThread, NULL)){
		printf("ERROR: PThread Join!\n");
	}	
*/
	waitpid(-1, &status, __WCLONE);
	err = pcap_stats(device, ps);
	if(err == -1){
		printf("ERROR on pcap_stats \n\t %s\n", pcap_geterr(device));
		goto cleanup;
	}
	printf("Received: %d, Dropped: %d, Interface Dropped: %d\n",ps->ps_recv,ps->ps_drop,ps->ps_ifdrop);
cleanup:
	halting = 1;
	pcap_close(device);
	free(queue);
	free(stack);
	free(ps);
fileclose:
	fclose(cap_file);
	return 0;

}
