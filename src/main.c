#include <stdio.h>
#include <signal.h>					// for signal
#include <errno.h>					// for errnp var.
#include <string.h>					// for string functions
#include <stdlib.h>					// for exit, strtol
#include <time.h>					// for time functions
#include <pthread.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>				// struct ip
#include <net/ethernet.h>			// struct ether_header
#include <arpa/inet.h>				// for inet_ntoa
#include <sys/stat.h>				// for 'struct stat', stat
#include <fcntl.h>					// for open
#include <sys/ioctl.h>				// for ioctl
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>					// struct ifreq, struct ifconf

#include <unistd.h>					// unlink
#include <zlib.h>					// for gzopen, gzwrite

#include "../include/ipstat_monitor.h"
#include "../include/lib_tree.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#else
#define VERSION "0.1"
#endif


#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <netinet/udp.h>			// struct udphdr

#define MAX_NUM_IFREQ 512			// for get_addr_by_dev

ITree	*st_tree = NULL;

typedef struct my_packet_key {
	u_int8_t	proto;
	u_int32_t	src;
	u_int32_t	dest;
	u_int16_t	src_port;
	u_int16_t	dest_port;
} MY_PACKET_KEY;

typedef struct my_packet_value {
	u_int		pkt;
	u_int		bytes;
	time_t		time_start;
	time_t		time_end;
} MY_PACKET_VALUE;



#define  MAX_PKT_SIZE	0xffff		// for pcap_open_live

//---------------------------------------------------------------------------------
static void 		termination(int signal);
static void* 		save(void *data);

static void 		pcap_callback(unsigned char *args, const struct pcap_pkthdr *hdr, const unsigned char *packet);
static void 		print_usage(FILE *);

static void 		add_packet(MY_PACKET_KEY *packet, int len);
static iint 		compare_tree (iconstpointer a, iconstpointer b);
static iint			traverse_sync (ipointer key, ipointer value, ipointer data);
static iint			traverse_free (ipointer key, ipointer value, ipointer data);

static u_int16_t 	agregate_port(u_int16_t port);
static void			name_port(u_int16_t port, char *str, size_t size);
static void			name_proto(u_int8_t proto, u_int16_t port, char *str, size_t);
static int			ipbyhost(uint32_t ip, char *host_name, size_t size);
static int			conv_time(time_t time, char *date);
static int			conv_date(time_t time, char *date);
static int			make_dir(char *dir);
static int			get_addr_by_dev(char *dev, char *addr, size_t size);
static int			save_pid(const char *file, const pid_t pid);
static int			m_daemon(const int nochdir, const int noclose);

int 				offset;
int 				datalink;
unsigned 			inactive = 0;
char				*dst_dir = NULL;
int					use_stdout = 1;
char 				*rule = NULL;
char 				*interface = NULL;
char				*addr_iface = NULL;
char				*pid_file = NULL;
pthread_t 			thread_id;
static sig_atomic_t do_exit = 0;

static pthread_mutex_t	ip_mutex = PTHREAD_MUTEX_INITIALIZER;
#define IP_LOCK 	pthread_mutex_lock(&ip_mutex)
#define IP_UNLOCK 	pthread_mutex_unlock(&ip_mutex)


//-------------------------------------------------------------------------------------------------
  
int 
main(int argc, char **argv)
{
	unsigned 			promisc = 0;
	int 				status;
    u_char 				i;
	pcap_t 				*pcap;
	struct bpf_program 	pf;
	char 				errbuf[PCAP_ERRBUF_SIZE];
	int 				op;

	while((op = getopt(argc, argv, "hpot:i:1:r:")) != EOF){
	switch(op){
		case 'p': 	promisc=1;
					break;
		
		case 'o': 	use_stdout=1;
					break;
		
		case 't': 	dst_dir=(char *)malloc(strlen(optarg)+1);
					strcpy(dst_dir, optarg);
					use_stdout = 0;
					break;		

		case 'r': 	rule=(char *)malloc(strlen(optarg)+1);
					strcpy(rule, optarg);
					break;		
		
		case 'i': 	interface=(char *)malloc(strlen(optarg)+1);
					strcpy(interface, optarg);
					break;
		
		case '1': 	inactive=strtol(optarg, NULL, 10);
				  	break;
		default: 	print_usage(stdout);
					exit(-1);
					break;
		}
	}

	if (!use_stdout) {
		printf("IPStat_monitor %s (c) 2005 Dmitry Kukuev, kornet@ipstat.perm.ru\n", VERSION);
		printf("This is part of IPStat project, see more http://ipstat.perm.ru/ \n");
	}

	if (!interface) { 
		print_usage(stderr); 
		exit(-1); 
	}

	if ((addr_iface = (char*) malloc(18)) == NULL) exit(1);
	if ((pid_file = (char*) malloc(FILENAME_MAX)) == NULL) exit(1);
	
	if (!get_addr_by_dev(interface, addr_iface, 18)) sprintf(addr_iface, "127.0.0.1");

	
	if (!inactive) inactive=1*600; // 10 min

	if (!use_stdout) {
		printf("\nOptions:\n");
		printf("---------------------------------------------\n");
		printf("Interface:\t\t%s\n", interface);
		printf("Directory to upload:\t%s\n", dst_dir);
		if(rule) printf("Rule:\t\t\t\"%s\"\n", rule);
		if(!promisc)	printf("Promisc mode is\t\toff\n");
		else			printf("Promisc mode is\t\ton\n");
		printf("Timeout to upload:\t%d seconds\n", inactive);
	}

	if (!use_stdout) m_daemon(0, 0);
	
	signal(SIGINT, (sig_t)termination);
	signal(SIGTERM, (sig_t)termination);
	signal(SIGKILL, (sig_t)termination);
	
	sprintf(pid_file, "/var/run/ipstat_monitor.%s", interface);
	save_pid(pid_file, getpid());
	
	pcap = pcap_open_live(interface, MAX_PKT_SIZE, promisc, 1000, errbuf);
	if (!pcap) {
    	    fprintf(stderr, "failed to open pcap interface: %s\n", errbuf);
    	    exit(errno);
	}
	datalink = pcap_datalink(pcap);
	for (i = 0;; i++)
		if (dlt[i].linktype == datalink || dlt[i].linktype == -1) {
			offset = dlt[i].offset_nl;
			break;
		}
	if (!use_stdout) printf("Type Libpcap:\t\t%s\n", dlt[i].descr);
	if (!use_stdout) printf("---------------------------------------------\n");

	if (rule) {
		if (-1 == pcap_compile(pcap, &pf, rule, 1, 0)) {
			fprintf(stderr, "failed to compile pcap: %s\n", pcap_geterr(pcap));
			exit(errno);
		}
		if (-1 == pcap_setfilter(pcap, &pf)) {
			fprintf(stderr, "failed to setfilter pcap: %s\n", pcap_geterr(pcap));
			exit(errno);
		}
	}

	st_tree = i_tree_new(&compare_tree);

	pthread_create(&thread_id, NULL, &save, NULL);

	while(do_exit==0) {
		status = pcap_dispatch(pcap, 1, pcap_callback, NULL);
		if (status == -1) {
			fprintf(stderr, "pcap dispatch error: %s\n", pcap_geterr(pcap));
			continue;
		}
	}
	pthread_kill(thread_id, SIGTERM);
	pthread_join(thread_id, NULL);
	if (st_tree) i_tree_destroy(st_tree);
	unlink(pid_file);
	exit(0);
} 		
//---------------------------------------------------------------------------------
static void 
pcap_callback(unsigned char *args, const struct pcap_pkthdr *hdr, const unsigned char *packet)
{
	u_short 							ether_type;
	struct ip 							*ip;
	register const struct ether_header 	*ep;
	register const struct sll_header 	*sllp;
	int									e_len;
	uint32_t                			src_port=0, dest_port=0;
	MY_PACKET_KEY						key;
		
	switch (datalink) {
#ifdef DLT_EN10MB
		case DLT_EN10MB:
	
			ep = (struct ether_header *)packet;
			ether_type = ntohs(ep->ether_type);
			packet += ETHER_HDR_LEN;
			e_len = hdr->len-sizeof(struct ether_header);
			break;
#endif
#ifdef DLT_LINUX_SLL
		case DLT_LINUX_SLL:
			if ( hdr->len < SLL_HDR_LEN) return;
			sllp = (struct sll_header *)packet;
			ether_type = ntohs(sllp->sll_protocol);
			e_len = hdr->len-sizeof(struct sll_header);
			if (ether_type <= ETHERMTU) return;
			packet += SLL_HDR_LEN;
			break;
#endif
		default:
			ether_type = 0xFFFF;
			e_len = hdr->len;
			break;
	}

	if (ether_type != 0xFFFF) {
recurse:
		if (ether_type == ETHERTYPE_VLAN) {
			ether_type = ntohs(*(u_int16_t *) (packet + 2));
			packet += 4;
			if (ether_type > ETHERMTU) goto recurse;
		}
		if (ether_type != ETHERTYPE_IP) return;
		ip = (struct ip *)packet;
	} else  ip = (struct ip *)(packet + offset);
	
	if (ntohs(ip->ip_off) & (IP_MF | IP_OFFMASK)) {
		src_port = dest_port = 0;
	}else if (ip->ip_p == IPPROTO_TCP) {
	    struct tcphdr 	*tcp = (struct tcphdr*)((unsigned char *)ip + ip->ip_hl*4);;
		src_port        = ntohs(tcp->th_sport);
		dest_port       = ntohs(tcp->th_dport);
	}else if (ip->ip_p == IPPROTO_UDP) {
		struct udphdr 	*udp = (struct udphdr*)((unsigned char *)ip + ip->ip_hl*4);

	    src_port		= ntohs(udp->uh_sport);
        dest_port		= ntohs(udp->uh_dport);
	}else {
        src_port = dest_port = 0;
    }

	key.proto	= ip->ip_p;
	key.src		= ip->ip_src.s_addr;
	key.dest	= ip->ip_dst.s_addr;
	key.src_port= agregate_port(src_port);
	key.dest_port= agregate_port(dest_port);
	
	add_packet(&key, e_len);
}

//---------------------------------------------------------------------------------
static void 
termination(int signal)
{
	do_exit = 1;
}		

static void* 
save(void *data){
	ITree		*backup = NULL;
	gzFile 		*fd = NULL;
	char		my_date[15];
	char		my_time[5];
	char		dir[FILENAME_MAX];
	
	do{
		sleep(inactive);
		IP_LOCK;
			backup = st_tree;
			st_tree = i_tree_new(&compare_tree);
		IP_UNLOCK;
		
		if (!use_stdout) {
			conv_date(time(NULL), my_date);
			conv_time(time(NULL), my_time);

			sprintf(dir, "%s/%s", dst_dir, my_date);
			make_dir(dir);	

			sprintf(dir, "%s/%s/%s", dst_dir, my_date, addr_iface);
			make_dir(dir);	

			sprintf(dir, "%s/%s/%s/%s.%s.gz", dst_dir, my_date, addr_iface, addr_iface, my_time);
			if ((fd = gzopen (dir, "a")) != NULL) { 
				i_tree_traverse(backup, &traverse_sync, I_IN_ORDER, fd);
				gzclose(fd);
			}
		}else{
			i_tree_traverse(backup, &traverse_sync, I_IN_ORDER, NULL);
		}
	
		i_tree_traverse(backup, &traverse_free, I_IN_ORDER, NULL);
		i_tree_destroy(backup);	
	}while (do_exit==0);
	pthread_exit(NULL);
}	
//---------------------------------------------------------------------------------

static void 
print_usage(FILE *f){
	fprintf(f, "Usage: ipstat_monitor {options}\nwhere {options} are:\n \
	-h\t\t print help screen and exit\n\
	-q\t\t quiet output\n\
	-d\t\t debug output\n\
	-p\t\t use promisc mode\n\
	-o\t\t output to stdout\n\
	-t dir\t\t select dir to unload\n\
	-r rule\t\t libpcap rule to capture packets\n\
	-i interface\t network interface to listen\n\
	-1 timeout\t period unload traffics (sec.)\n");
}

static void
add_packet(MY_PACKET_KEY *packet, int len)
{
	ipointer			ptr;
	MY_PACKET_KEY		*key;
	MY_PACKET_VALUE		*value;

	IP_LOCK;
		if ((ptr = i_tree_lookup(st_tree, (ipointer) packet)) != NULL) {
			value = (MY_PACKET_VALUE*) ptr;
			value->pkt++;
			value->bytes+=len;
			value->time_end = time(NULL);
		} else {
			if ((key = (MY_PACKET_KEY*) malloc(sizeof(MY_PACKET_KEY))) == NULL) {
				IP_UNLOCK;	
				return;
			}
			if ((value = (MY_PACKET_VALUE*) malloc(sizeof(MY_PACKET_VALUE))) == NULL) {
				free(key);
				IP_UNLOCK;
				return;
			}
			memcpy(key, packet, sizeof(MY_PACKET_KEY));

			value->pkt 			= 1;
			value->bytes 		= len;
			value->time_start	= time(NULL);
			value->time_end		= time(NULL);
			i_tree_insert(st_tree, key, value);
		}
	IP_UNLOCK;
}

static iint 
compare_tree (iconstpointer a, iconstpointer b)
{
	MY_PACKET_KEY *key1 = (MY_PACKET_KEY*) a;
	MY_PACKET_KEY *key2 = (MY_PACKET_KEY*) b;
	
	return memcmp(key1, key2, sizeof(MY_PACKET_KEY));
}


static iint 
traverse_sync (ipointer key, ipointer value, ipointer data)
{
	gzFile			*fd			= (gzFile*) data;
	MY_PACKET_KEY	*t_key 		= (MY_PACKET_KEY*) key;
	MY_PACKET_VALUE	*t_value 	= (MY_PACKET_VALUE*) value;
	char			src[18]="", dst[18]="", src_port[18]="", dest_port[18]="", proto[18]="";
	char			buffer[1024];
	
	ipbyhost(t_key->src, src, sizeof(src));
	ipbyhost(t_key->dest, dst, sizeof(dst));
	name_port(t_key->src_port, src_port, sizeof(src_port));
	name_port(t_key->dest_port, dest_port, sizeof(dest_port));
	
	name_proto(t_key->proto, t_key->dest_port, proto, sizeof(proto));
		
	sprintf(buffer, "%s|%s|%s|%s|%s|%u|%u|%u|%u|%u\n", src, dst, src_port, dest_port, proto, t_value->pkt, t_value->bytes, t_value->pkt, (int) t_value->time_start, (int) time(NULL));

	if (fd) 	gzwrite (fd, buffer, strlen(buffer));
	else		fprintf(stdout, "%s", buffer);
	return 0;
}

static iint 
traverse_free (ipointer key, ipointer value, ipointer data)
{
	if (key) free(key);
	if (value) free(value);
		
	return 0;
}


static int
save_pid(const char *file, const pid_t pid)
{
    FILE    *fd;
    char    str_pid[7];
		
    sprintf(str_pid, "%d", (int) pid);
	
    if ((fd = fopen(file, "w"))!=NULL){
        fwrite(str_pid, 1, strlen(str_pid), fd);
        fclose(fd);
    }else return 0;
    return 1;
}

static u_int16_t
agregate_port(u_int16_t port)
{
	u_int16_t tmp = 0;

	if (port<=1024) tmp = port;
	else if (port>1024 && port<=9999)    tmp = 1025;
	else if (port>=10000 && port<=19999) tmp = 10000;
	else if (port>=20000 && port<=29999) tmp = 20000;
	else if (port>=30000 && port<=39999) tmp = 30000;
	else if (port>=40000 && port<=49999) tmp = 40000;
	else if (port>=50000 && port<=59999) tmp = 50000;
	else if (port>=60000)                tmp = 60000;
	return tmp;
}

static void
name_port(u_int16_t port, char *str, size_t size)
{
	if (port <= 1024) snprintf(str, size-1, "%d", port);
	else if (port>1024 && port<=9999)    snprintf(str, size-1, "1K_9K_Port");
	else if (port>=10000 && port<=19999) snprintf(str, size-1, "10K_19K_Port");
	else if (port>=20000 && port<=29999) snprintf(str, size-1, "20K_29K_Port");
	else if (port>=30000 && port<=39999) snprintf(str, size-1, "30K_39K_Port");
	else if (port>=40000 && port<=49999) snprintf(str, size-1, "40K_49K_Port");
	else if (port>=50000 && port<=59999) snprintf(str, size-1, "50K_59K_Port");
	else if (port>=60000)                snprintf(str, size-1, "60K_65K_Port");
}

static void
name_proto(u_int8_t proto, u_int16_t port, char *str, size_t size)
{
    if (proto == 0) {
		strncpy(str, "IP", size-1);
		return;
    } else if (proto == 1) {
		strncpy(str, "ICMP", size-1);
		return;
    } else if (proto == 2) {
		strncpy(str, "IGMP", size-1);
		return;
    } else if (proto == 6) {
        strncpy(str, "TCP", size-1);
    } else if (proto == 17) {
        strncpy(str, "UDP", size-1);
    } else if (proto == 47) {
		strncpy(str, "GRE", size-1);
	return;
    } else if (proto == 94) {
		strncpy(str, "IPIP", size-1);
		return;
    } else {
        sprintf(str, "%d", proto);
        return;
    }
    if (port == 7) strncat(str, "-ECHO", size-1);else
    if (port == 13) strncat(str, "-DAYTIME", size-1); else
    if (port == 20) strncat(str, "-FTP", size-1); else
    if (port == 21) strncat(str, "-FTP", size-1); else
    if (port == 22) strncat(str, "-SSH", size-1); else
    if (port == 23) strncat(str, "-TELNET", size-1); else
    if (port == 25) strncat(str, "-SMTP", size-1); else
    if (port == 37) strncat(str, "-TIME", size-1); else
    if (port == 43) strncat(str, "-WHOIS", size-1); else
    if (port == 53) strncat(str, "-DOMAIN", size-1); else
    if (port == 80) strncat(str, "-WWW", size-1); else
    if (port == 88) strncat(str, "-KERBEROS", size-1); else
    if (port == 109) strncat(str, "-POP2", size-1); else
    if (port == 110) strncat(str, "-POP3", size-1); else
    if (port == 123) strncat(str, "-NTP", size-1); else
    if (port == 137) strncat(str, "-NETBIOS_NS", size-1); else
    if (port == 138) strncat(str, "-NETBIOS_DGM", size-1); else
    if (port == 139) strncat(str, "-NETBIOS_SSN", size-1); else
    if (port == 143) strncat(str, "-IMAP2", size-1); else
    if (port == 389) strncat(str, "-LDAP", size-1); else
    if (port == 443) strncat(str, "-HTTPS", size-1); else
    strncat(str, "-Other", size-1);

}

static int
ipbyhost(uint32_t ip, char *host_name, size_t size)
{
    struct in_addr tmp_ip;
                                                                                
    if (host_name == NULL) return 0;
    tmp_ip.s_addr = ip;
    strncpy(host_name, inet_ntoa(tmp_ip), size-1);
    return 1;
}
static int
conv_time(time_t time, char *date)
{
	struct tm now_date;

	localtime_r(&time, &now_date);
	strftime(date, 5, "%H%M", &now_date);
	return 1;
}

static int
conv_date(time_t time, char *date)
{
	struct tm now_date;

	localtime_r(&time, &now_date);
	strftime(date, 11, "%G_%m_%d", &now_date);
	return 1;
}

static int
make_dir(char *dir)
{
 struct stat file_stat;
                                                                                
 if (stat(dir, &file_stat)==-1) mkdir(dir, S_IRWXU+S_IRWXG);
 return 1;
}

static int
get_addr_by_dev(char *dev, char *addr, size_t size)
{
    struct ifconf Ifc;
    struct ifreq IfcBuf[MAX_NUM_IFREQ], *pIfr;
    int num_ifreq, i, fd, ret = 0;
    struct sockaddr_in addrtmp;
    
    Ifc.ifc_len=sizeof(IfcBuf);
    Ifc.ifc_buf=(char *)IfcBuf;
    
    if ((fd=socket(AF_INET, SOCK_DGRAM, 0))<0) {
        fprintf(stderr, "ERROR socket(): \n");
        return 0;
    }
    if (ioctl(fd, SIOCGIFCONF, &Ifc)<0) {
        fprintf(stderr, "ERROR ioctl(SIOCGIFCONF): \n");
        close(fd);
        return 0;
    }
    num_ifreq=Ifc.ifc_len/sizeof(struct ifreq);
    
    for (pIfr=Ifc.ifc_req, i=0; i<num_ifreq; ++pIfr, ++i) {
        if (pIfr->ifr_addr.sa_family!=AF_INET) continue;
	if (strcmp(pIfr->ifr_name, dev)==0) {
	    if (ioctl(fd, SIOCGIFADDR, pIfr)<0) {
                fprintf(stderr, "ERROR ioctl(SIOCGIFADDR): \n");
                continue;
            }
            memcpy(&addrtmp, &(pIfr->ifr_addr), sizeof(addrtmp));
	    bzero(addr, size);
            strncpy(addr, inet_ntoa(addrtmp.sin_addr), size-1);
	    ret = 1;
	    break;
	}	
    }
    return ret;
}


static int
m_daemon(const int nochdir, const int noclose)
{
    int fd;

    switch (fork()) {
        case -1:
	            return (-1);
	case 0:
	            break;
	default:
	            _exit(0);
    }

    if (setsid() == -1)
        return (-1);

    if (!nochdir)
        (void)chdir("/");

    if (!noclose && (fd = open("/dev/null", O_RDWR, 0)) != -1) {
        (void)dup2(fd, STDIN_FILENO);
        (void)dup2(fd, STDOUT_FILENO);
        (void)dup2(fd, STDERR_FILENO);
        if (fd > 2)
            (void)close(fd);
    }
    return 1;
}
