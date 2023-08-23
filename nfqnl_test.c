#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <stdbool.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

/* returns packet id */

unsigned char* harmfulSite = NULL;
unsigned char* host_str=NULL;
int check=0;
void dump2(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);	
	}
	printf("\n");
}

unsigned char* get_http_start_address(unsigned char* buf) {
    // Calculate ip header length (lower 4its of 1st bytes) & word to byte
    int ip_header_len = (buf[0] & 0x0F) * 4;

    // Calculate tcp header length (higher 4bits of 13th bytes) BUT it is word. so convert it to byte
    int tcp_header_len = ((buf[ip_header_len + 12] >> 4) & 0x0F) * 4;
    // Calculate HTTP start address
    unsigned char* http_start = buf + ip_header_len + tcp_header_len;

    return http_start;
}

bool isHttp(unsigned char* buf, int size) {
    unsigned char* http_start = get_http_start_address(buf);
    if (http_start - buf >= size) {
        return false;
    }

    const char* methods[] = {
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT"
    };
    for (int i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
		
        if (strncmp((char*)http_start, methods[i], strlen(methods[i])) == 0) {
            return true;
        }
    }

    return false;
}

bool isHarmful(unsigned char* site, unsigned char* hSite){
	if(strncmp(site,hSite,strlen(hSite)+1)==0){
		return true;
	}
	return false;
}

unsigned char* dump(unsigned char* buf, int size) {

	unsigned char* http_start=get_http_start_address(buf);

	int method_pass=0;
	int start_idx;
	for(int i=0;i<strlen((char*)http_start);i++){
		if(http_start[i]==0x0d && http_start[i+1]==0x0a){
			start_idx=i+2;
			break;
		}
	}
	
	http_start= http_start + start_idx + 6; //host index pass


    unsigned char* host_str = malloc(12);  // Dynamically allocate memory
    if (!host_str) {
        return NULL;  // Memory allocation failed
    }
    memset(host_str, 0, 12);  
	
	for(int i=0;i<strlen((char*)http_start);i++){
		if(http_start[i]==0x0d && http_start[i+1]==0x0a){
			break;
		}
		host_str[i]=http_start[i];
	}

    printf("net is %s\n\n", host_str);

	return host_str;
}


static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
/* 		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id); */
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

/* 		printf("hw_src_addr="); */
/* 		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]); */
	} 

	mark = nfq_get_nfmark(tb);
/* 	if (mark)
		printf("mark=%u ", mark); */

	ifi = nfq_get_indev(tb);
/* 	if (ifi)
		printf("indev=%u ", ifi); */

	ifi = nfq_get_outdev(tb);
/* 	if (ifi)
		printf("outdev=%u ", ifi); */
	ifi = nfq_get_physindev(tb);
/* 	if (ifi)
		printf("physindev=%u ", ifi); */

	ifi = nfq_get_physoutdev(tb);
/* 	if (ifi)
		printf("physoutdev=%u ", ifi); */

	ret = nfq_get_payload(tb, &data);
/* 	if (ret >= 0)
		printf("payload_len=%d\n", ret); */

	if(isHttp(data,ret)){
    	host_str=dump(data,ret);
		check=1;
		printf("is here? %s \n\n",host_str);
	}


/* 	fputc('\n', stdout); */

	return id;
}



// 인자를 통해 ping을 보내고, output을 내고, input을 받을 때,
// 인자의 domain name과 다를 경우 host값 검증 
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
/* 	printf("entering callback\n"); */

	printf("log!\n");
	if (check==1&& isHarmful(host_str, harmfulSite)) {
    	printf("Harmful site detected: %s\n", host_str);
		
    	return nfq_set_verdict(qh, id, NF_DROP, 0, NULL); // Drop packet
	}
	else{
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
	check=0;
	host_str=NULL;

}


int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <harmful_site>\n", argv[0]);
		exit(1);
	}
	harmfulSite= (unsigned char*)argv[1];
	printf("argu is %s\n",harmfulSite);
	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
/* 			printf("pkt received\n"); */
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
