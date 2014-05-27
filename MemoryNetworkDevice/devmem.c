#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/netpoll.h>
#include <linux/inet.h>
#include <linux/etherdevice.h>
#include <linux/cage.h>

MODULE_AUTHOR("Sarah Laing");
MODULE_LICENSE("GPL");

struct net_device *devmem;
struct memevent_packet *head;

struct eth_header{
	unsigned char src[6];
	unsigned char dest[6];
	unsigned short type;
} __attribute__((packed));

struct eth_header *eth;

struct packet{
	struct eth_header eth;
	struct memevent_packet mp;
} __attribute__((packed));


int devmem_open(struct net_device *dev){

	memcpy(dev->dev_addr, "\0DEVMEM", ETH_ALEN);
	head = kmalloc(sizeof(struct memevent_packet)*10, GFP_KERNEL);
	set_queue_start(head);
	eth = kmalloc(sizeof(struct eth_header), GFP_KERNEL);
	memcpy(eth->src, dev->dev_addr, ETH_ALEN);
	memcpy(eth->dest, dev->dev_addr, ETH_ALEN);
	eth->type = 0xb588;
	return 0;
}

int devmem_close(struct net_device *dev){
	set_queue_start(NULL);
	kfree(head);
	kfree(eth);
	return 0;
}

netdev_tx_t devmem_tx(struct sk_buff *skb, struct net_device *dev){
	struct memevent_packet *mp;
	struct packet *p;
	struct sk_buff *sb;
	int ret;
	mp = dequeue();
	if(!mp){
		return 0;
	}
	sb = dev_alloc_skb(68);
	if(!sb){
		if(printk_ratelimit())
		printk(KERN_NOTICE "No skb allocated\n");
		return 0;
	}
	p = kmalloc(sizeof(struct packet), GFP_KERNEL);
	p->eth = *eth;
	p->mp = *mp;
	memcpy(skb_put(sb, 66), p, 66);

	sb->dev = dev;
	sb->protocol = eth_type_trans(sb, dev);
	sb->ip_summed = CHECKSUM_UNNECESSARY;
	ret = netif_rx(sb);
	kfree(p);
	return NETDEV_TX_OK;
}
static const struct net_device_ops devmem_ops = {
	.ndo_open	= devmem_open,
	.ndo_stop	= devmem_close,
	.ndo_start_xmit = devmem_tx,
};

void devmem_setup(struct net_device *dev){
	ether_setup(dev);
	dev->flags 		|= IFF_NOARP;
	dev->netdev_ops		= &devmem_ops;
}


void cleanup_module(void){
	unregister_netdev(devmem);
	free_netdev(devmem);
	return;
}

static int __init devmem_start(void){
	int ret = -ENOMEM;
	
	devmem = alloc_netdev(0, "me", devmem_setup);
	if(devmem == NULL)
		goto outro;
	ret = -ENODEV;
	
	if(register_netdev(devmem)){
		printk(KERN_INFO "Error Registering me Device\n");
		goto outro;
	}
	ret = 0;
outro:
	if(ret)
		cleanup_module();
	return ret;
}


module_init(devmem_start);

