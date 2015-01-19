#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/kmod.h>
#include <linux/cage.h>
#include <linux/filter.h>
#include <linux/slab.h>

MODULE_AUTHOR("Sarah Laing");
MODULE_LICENSE("GPL");

struct cage_filter *filter;

//static int num = 0;
//static char *program[255];
static int type = 0;
//static unsigned long begin_address = 0;
//static unsigned long end_address = 0;

//module_param(begin_address, ulong, 0);
//module_param(end_address, ulong, 0);
//module_param(num, int, 0);
//module_param_array(program, charp,NULL ,0);
module_param(type, int, 0);

int check_filter(struct sock_filter *filter, unsigned int len){
	int pc;
	struct sock_filter *filt;
	u16 code;
	for(pc = 0; pc < len; pc++){
		filt = &filter[pc];
		code = filt->code;
		switch(code){
	
		case BPF_S_LD_W_ABS:{
			filt->code = BPF_S_ANC_CAGE_LD_W;
			continue;
		}
		}
	}
	return 0;
}

void create_filter(void){
	int ret;

/*	CANARY FILTER
	struct sock_filter insns[] = {
		BPF_STMT(BPF_MISC+BPF_LDC,BPF_GET_RWX),		//load rwx flags
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x02, 0, 6),	//write flag set
		BPF_STMT(BPF_MISC+BPF_LDC, BPF_LOAD_STORED_1),		//load from reg 1 which is stored ea
		BPF_STMT(BPF_MISC+BPF_TAX,0),		//put stored ea into X
		BPF_STMT(BPF_MISC+BPF_LDC,BPF_GET_EA),		//load current ea
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_X,0,10,0),	//stored ea != current ea
		BPF_STMT(BPF_MISC+BPF_STC,1),		//store ea in reg 1
		BPF_STMT(BPF_RET+BPF_K, 1),		//show write packet
		
		BPF_STMT(BPF_MISC+BPF_LDC,BPF_LOAD_STORED_1),		//load from reg 1 which is stored ea
		BPF_STMT(BPF_MISC+BPF_TAX,0),		//put stored ea into X
		BPF_STMT(BPF_MISC+BPF_LDC,BPF_GET_EA),		//load current ea
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_X,0,0,3),	//stored ea == current ea
		BPF_STMT(BPF_MISC+BPF_LDC,BPF_GET_RWX),		//load rwx flags
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x00, 0, 2),	//read flag set
		BPF_STMT(BPF_RET+BPF_K, 1),		//packet
		BPF_STMT(BPF_RET+BPF_K, 0),		//no packet
		BPF_STMT(BPF_RET+BPF_K, -1),		//segfault	
	};	
*/
/*	RANGE CHECKING FILTER
	struct sock_filter insns[] = {
		BPF_STMT(BPF_LD+BPF_IMM,0XFFFFFFFF),		//load k into A where k = 0xFFFFFFFF
		BPF_STMT(BPF_ALU+BPF_LSH+BPF_K, 32),		//left shift A by 32, A = 0xFFFFFFFF00000000
		BPF_STMT(BPF_ALU+BPF_OR+BPF_K, 0XFFFFFFF6),	//or A with k, where k = 0xFFFFFFF6, A = FFFFFFFFFFFFFFF6
		BPF_STMT(BPF_MISC+BPF_TAX,0),			//transfer A to X
		BPF_STMT(BPF_MISC+BPF_LDC,BPF_GET_DATA_EA),	//load data @ ea into A
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 3, 0),	//if data @ ea == 0, return 1	
		BPF_STMT(BPF_ALU+BPF_SUB+BPF_K, 10),		//else subtract 10 (hack for testing A < 10
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 1, 0),	//if A == 0, data @ ea was 10, return 1
		BPF_JUMP(BPF_JMP+BPF_JGE+BPF_X, 0, 0, 1),	//if A >= X, data @ ea was <= 10, return 1
		BPF_STMT(BPF_RET+BPF_K, 1),
		BPF_STMT(BPF_RET+BPF_K, -1),
	};
*/
/*	ALWAYS READ, ALWAYS WRITTEN
	struct sock_filter insns[] = {
		BPF_STMT(BPF_MISC+BPF_LDC,BPF_GET_RWX),		//load rwx flags
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x02, 0, 1),	//oracle tells you to watch for writes or reads
		BPF_STMT(BPF_RET+BPF_K, 1),		
		BPF_STMT(BPF_RET+BPF_K, -1),
		
	};
*/
/*	WRITE, READ, REPEAT
	struct sock_filter insns[] = {
		BPF_STMT(BPF_MISC+BPF_LDC,BPF_LOAD_STORED_2),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 2, 0),	
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 1, 7, 0),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 2, 0, 5),
		BPF_STMT(BPF_MISC+BPF_LDC,BPF_GET_RWX),		//load rwx flags
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x02, 0, 3),	//writes
		BPF_STMT(BPF_LD+BPF_IMM,1),		//load k into A where k = 1
		BPF_STMT(BPF_MISC+BPF_STC,2),		//store ea in reg 2
		BPF_STMT(BPF_RET+BPF_K, 1),		
		BPF_STMT(BPF_RET+BPF_K, -1),
		BPF_STMT(BPF_MISC+BPF_LDC,BPF_GET_RWX),		//load rwx flags
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x00, 0, 3),	//watching for reads
		BPF_STMT(BPF_LD+BPF_IMM,2),		//load k into A where k = 2
		BPF_STMT(BPF_MISC+BPF_STC,2),		//store A in reg 2
		BPF_STMT(BPF_RET+BPF_K, 1),		
		BPF_STMT(BPF_RET+BPF_K, -1),
			
	};
*/
/*	SHORT LIST OF INSTRUCTIONS
	struct sock_filter insns[] = {
		BPF_STMT(BPF_MISC+BPF_LDC,BPF_GET_EIP),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x400513, 4, 0),	//FIX JUMP VALUES
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x40051e, 3, 0),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x400537, 2, 0),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x40053e, 1, 0),	//FIX JUMP VALUES
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x400552, 0, 1),
		BPF_STMT(BPF_RET+BPF_K, 1),		
		BPF_STMT(BPF_RET+BPF_K, -1),	
	};
*/

	struct sock_filter insns[] = {
		BPF_STMT(BPF_MISC+BPF_LDC,BPF_LOAD_STORED_1),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0, 3),
		BPF_STMT(BPF_MISC+BPF_LDC,BPF_GET_DATA_EA),	//load data @ ea into A
		BPF_STMT(BPF_MISC+BPF_STC,1),		//store data @ ea in reg 1
		BPF_STMT(BPF_RET+BPF_K, 1),		
		BPF_STMT(BPF_MISC+BPF_TAX,0),		//put stored data @ ea into X
		BPF_STMT(BPF_MISC+BPF_LDC,BPF_GET_DATA_EA),	//load data @ ea into A
		BPF_JUMP(BPF_JMP+BPF_JGT+BPF_X, 0, 1, 0),	//change jump destinations around for decreasing
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_X, 0, 1, 2),
		BPF_STMT(BPF_MISC+BPF_STC,1),		//store data @ ea in reg 1	
		BPF_STMT(BPF_RET+BPF_K, 1),		
		BPF_STMT(BPF_RET+BPF_K, -1),	
		
	};

	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(insns)/sizeof(insns[0])),
		.filter = insns,
	};
	ret = sk_chk_filter(prog.filter, prog.len);
	if(ret != 0)
		printk("Rule set illegal\n\n\n");
	//check_filter(prog.filter, prog.len);
      /*for(ret = 0; ret < prog.len; ret ++){
              printk("Instructions %u\n",prog.filter[ret].code);
            }
	*/
	filter = kmalloc(sizeof(struct cage_filter)+(prog.len*sizeof(struct sock_filter)), GFP_KERNEL);
	if(!filter)	
		printk("KMALLOC FAILED\n");
	memcpy(filter->insns, prog.filter, (sizeof(prog.filter)*prog.len));
	//filter->start_address = begin_address;
	//filter->end_address = end_address;
	//filter->num_events = num;
	filter->type = (unsigned char)type;
}

static int __init temporal_start(void){
	create_filter();
	set_cage_filter(filter);
	return 0;
}

static void __exit temporal_end(void){
	set_cage_filter(NULL);
	cage_set_flag(0);
	cage_set_stored_ea(0);
	cage_clear_rax();
	cage_clear_eip();
	cage_clear_values();
	kfree(filter);
	return;
}

module_init(temporal_start);
module_exit(temporal_end);
