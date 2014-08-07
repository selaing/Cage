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

static int num = 0;
static char *program[255];
static int type = 0;
static unsigned long begin_address = 0;
static unsigned long end_address = 0;
static unsigned char insn[15];

module_param(begin_address, ulong, 0);
module_param(end_address, ulong, 0);
module_param(num, int, 0);
module_param(insn, byte, NULL, 0);
module_param_array(program, charp,NULL ,0);
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

/*		//TEMPORAL FILTER
	struct sock_filter insns[] = {
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS,1 ),	//effective address from packet
		BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, begin_address, 0, 7),	//>= begin address
		BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, end_address,6,0),	
		BPF_STMT(BPF_ALU+BPF_SUB+BPF_K, end_address),
		BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, end_address, 1, 0),	//<= end address
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0,3),
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 2),		//current num of events
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, num, 0, 2),	//num events to reach before packet
		BPF_STMT(BPF_RET+BPF_K, 1),					//emit packet
		BPF_STMT(BPF_RET+BPF_K, 0),					//no match on address range
		BPF_STMT(BPF_RET+BPF_K, -1),					//not enough events for packet
	};
*/

/*		//DATA-OVERWRITING FILTER
 	struct sock_filter insns[] = {
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS,1 ),	//effective address from packet
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, begin_address, 1, 0),	//= begin address
		BPF_STMT(BPF_RET+BPF_K, 0),
		BPF_STMT(BPF_RET+BPF_K, num),
	};
*/
 	
/*		//INSTRUCTION-OVERWRITING FILTER
 	struct sock_filter insns[] = {
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS,3 ),	//effective address from packet
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, begin_address, 1, 0),	//= begin address
		BPF_STMT(BPF_RET+BPF_K, 0),
		BPF_STMT(BPF_RET+BPF_K, num),
	};
*/
		//BUFFER-VIEWING FILTER
	struct sock_filter insns[] = {
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 3),	//load eip
		BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, begin_address, 0, 6),	//>= begin address
		BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, end_address,5,0),	
		BPF_STMT(BPF_ALU+BPF_SUB+BPF_K, end_address),
		BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, end_address, 1, 0),	//<= end address
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, 0,2),
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 6),	//load rax
		BPF_STMT(BPF_RET+BPF_A,0),		//return rax
		
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 5),	//load stored_ea
		BPF_STMT(BPF_MISC+BPF_TAX,0),		//put A in X
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 1),	//load ea
		BPF_JUMP(BPF_JMP+BPF_JGE+BPF_X, 0, 0, 6),	//if store_ea >= ea
		BPF_STMT(BPF_MISC+BPF_TXA,0),		//put stored_ea back in A
		BPF_STMT(BPF_ALU+BPF_ADD+BPF_K, num),	//add num to stored_ea
		BPF_STMT(BPF_MISC+BPF_TAX,0),		//put end of range into X
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 1),	//load ea
		BPF_JUMP(BPF_JMP+BPF_JGT+BPF_X,0,1,0),	//jump if greater than end of range to return 0
		
		BPF_STMT(BPF_RET+BPF_K, 1),		//return 1
		BPF_STMT(BPF_RET+BPF_K, 0),
	};

/*		//BUFFER FINDING FILTER
 	struct sock_filter insns[] = {
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 5),	//load stored_ea
		BPF_STMT(BPF_MISC+BPF_TAX,0),		//put A in X
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 1),	//load ea
		BPF_STMT(BPF_ALU+BPF_SUB+BPF_X, 0),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x08, 0,1),
		BPF_STMT(BPF_RET+BPF_K, 1),		//return 1
		BPF_STMT(BPF_RET+BPF_K, 0),
	};
*/
	
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(insns)/sizeof(insns[0])),
		.filter = insns,
	};
	ret = sk_chk_filter(prog.filter, prog.len);
	if(ret != 0)
		printk("Rule set illegal\n\n\n");
	check_filter(prog.filter, prog.len);
	filter = kmalloc(sizeof(struct cage_filter)+(prog.len*sizeof(struct sock_filter)), GFP_KERNEL);
	if(!filter)	
		printk("KMALLOC FAILED\n");
	memcpy(filter->insns, prog.filter, (sizeof(prog.filter)*prog.len));
	filter->start_address = begin_address;
	filter->end_address = (unsigned long)insn;
	filter->num_events = num;
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
	kfree(filter);
	return;
}

module_init(temporal_start);
module_exit(temporal_end);
