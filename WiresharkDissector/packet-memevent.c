/*Memory Event Dissector*/

#include "config.h"
#include <epan/packet.h>
#include <udis86.h>

#define CREATE	0x08
#define READ	0x04
#define WRITE	0x02
#define EXECUTE 0x01
#define SRC_LABEL 0xffe00000
#define DEST_LABEL 0x001ffc00
#define PTE 0x000003ff

static int proto_memevent = -1;
static int memevent_readflag = -1;
static int memevent_writeflag = -1;
static int memevent_executeflag = -1;
static int memevent_creationflag = -1;
static gint ett_memevent = -1;
static int memevent_flags = -1;
static gint ett_memeventsub = -1;
static int memevent_src = -1;
static int memevent_dest = -1;
static int memevent_slabel = -1;
static int memevent_dlabel = -1;
static int memevent_pte = -1;
static int memevent_pid = -1;
static int memevent_uid = -1;
static int memevent_data = -1;

typedef struct{
unsigned char inst[35];
}inst;
static int memevent_inst = -1;

char buf[35];
char buf2[240];

void disassemble(void){
	if(buf[0] == NULL)
		goto outro;

	ud_t ud_obj;
	ud_init(&ud_obj);
	ud_set_input_buffer(&ud_obj, buf, 32);
	ud_set_mode(&ud_obj, 64);
	ud_set_syntax(&ud_obj, UD_SYN_INTEL);
	if(ud_disassemble(&ud_obj)){
		snprintf(buf2, 240, "%s", ud_insn_asm(&ud_obj));
		if(buf2[0] != NULL){
		}	
	}
outro:
	return;
}


static void dissect_memevent(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){
	gint offset = 0;
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MEMEVENT");
	col_clear(pinfo->cinfo, COL_INFO);
	if(tree){
		proto_item *ti = NULL;
		proto_item *memevent_tree = NULL;
		proto_item *memevent_subtree = NULL;
		proto_item *to = NULL;
		proto_item *in = NULL;

		ti = proto_tree_add_item(tree, proto_memevent, tvb, 0, -1, ENC_NA);
		memevent_tree = proto_item_add_subtree(ti, ett_memevent);
		
		proto_tree_add_item(memevent_tree, memevent_src, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;
		proto_tree_add_item(memevent_tree, memevent_dest, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;
		proto_tree_add_item(memevent_tree, memevent_slabel, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(memevent_tree, memevent_dlabel, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(memevent_tree, memevent_pte, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
	
		to = proto_tree_add_item(memevent_tree, memevent_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		
		memevent_subtree = proto_item_add_subtree(to, ett_memeventsub);
		proto_tree_add_item(memevent_subtree, memevent_creationflag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(memevent_subtree, memevent_readflag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(memevent_subtree, memevent_writeflag, tvb, offset,1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(memevent_subtree, memevent_executeflag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;
		in = proto_tree_add_item(memevent_tree, memevent_inst, tvb, offset, 15, ENC_LITTLE_ENDIAN);
		offset += 15;
		proto_tree_add_item(memevent_tree, memevent_pid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(memevent_tree, memevent_uid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(memevent_tree, memevent_data, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		
		snprintf(buf, 30, "%s", in->finfo->value.value.string);
		disassemble();
		proto_item_set_text(in, "Instruction: ");
		proto_item_append_text(in, "%s", buf2);
	}
}

void proto_register_memevent(void){

	static inst *in;
	memevent_inst = in->inst;
	static hf_register_info hf[] = {
		{&memevent_flags, {"MEMEVENT FLAGS", "flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}},		
		{&memevent_creationflag, {"New vm_area Created", "create", FT_BOOLEAN, 8, NULL, CREATE, NULL, HFILL}},
		{&memevent_readflag,{"MEMEVENT READ FLAG", "read", FT_BOOLEAN, 8, NULL, READ, NULL, HFILL}},
		{&memevent_writeflag,{"MEMEVENT WRITE FLAG", "write", FT_BOOLEAN, 8, NULL, WRITE, NULL, HFILL}},
		{&memevent_executeflag,{"MEMEVENT EXECUTE FLAG", "execute", FT_BOOLEAN, 8, NULL, EXECUTE, NULL, HFILL}},
		{&memevent_src, {"Instruction Pointer", "eip", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&memevent_dest,{"Effective Address", "ea", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&memevent_slabel, {"Instruction Label", "eal", FT_UINT32, BASE_HEX, NULL, SRC_LABEL, NULL, HFILL}},
		{&memevent_dlabel, {"Effective Address Label", "eipl", FT_UINT32, BASE_HEX, NULL, DEST_LABEL, NULL, HFILL}},
		{&memevent_pte, {"EA PTE Meta-Data", "pte", FT_UINT32, BASE_HEX, NULL, PTE, NULL, HFILL}},
		{&memevent_pid, {"PID", "pid", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
		{&memevent_uid, {"UID", "uid", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
		{&memevent_data, {"Data at Effective Address", "data", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},
		{&memevent_inst, {"Instruction", "insn", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}}
	};

	static gint *ett[] = {
		&ett_memevent, &ett_memeventsub
	};

	proto_memevent = proto_register_protocol("MEMEVENT Protocol", "MEMEVENT", "memevent");
	register_dissector("MEMEVENT", dissect_memevent, proto_memevent);
	proto_register_field_array(proto_memevent, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_memevent(void){
	static dissector_handle_t memevent_handle;
	memevent_handle = create_dissector_handle(dissect_memevent, proto_memevent);
	dissector_add_uint("ethertype", 0x88b5, memevent_handle);
}


