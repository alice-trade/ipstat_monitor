
#ifndef _IPSTAT_MONITOR_H
#define _IPSTAT_MONITOR_H

#ifdef LINUX
	extern "C" {
        #include <pcap.h>
	}
#else
	#include <pcap.h>
#endif

struct DLT {
	int 	linktype;
	int 	offset_link;
	int 	offset_nl;
	int		offset_nl_nosnap;
	char	*descr;
};

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100			/* IEEE 802.1Q VLAN tagging */
#endif
#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800				/* IP protocol */
#endif

#ifdef DLT_LINUX_SLL
#define SLL_HDR_LEN 16          		/* total header length */
#define SLL_ADDRLEN 8           		/* length of address field */

struct sll_header {
	u_int16_t	sll_pkttype;  			/* packet type */
	u_int16_t	sll_hatype;   			/* link-layer address type */
	u_int16_t	sll_halen;    			/* link-layer address length */
	u_int8_t	sll_addr[SLL_ADDRLEN]; 	/* link-layer address */
	u_int16_t	sll_protocol; 			/* protocol */
};
#endif

struct captured_data {
	pcap_t *pcap;
	int datalink;
	int offset;
	u_char link_type_idx;
};

struct DLT dlt[] = {
#ifdef DLT_NULL
        {DLT_NULL, 0, 4, 4, "NULL"},
#endif
#ifdef DLT_EN10MB
        {DLT_EN10MB, 12, 14, 17, "EN10MB"},
#endif
#ifdef DLT_IEEE802
        {DLT_IEEE802, 14, 22, 17, "IEEE802"},
#endif
#ifdef DLT_ARCNET
        {DLT_ARCNET, 2 , 6, 6, "ARCNET"},
#endif
#ifdef DLT_SLIP
        {DLT_SLIP, -1, 16, 16, "SLIP"},
#endif
#ifdef DLT_PPP
        {DLT_PPP, 2, 4, 4, "PPP"},
#endif
#ifdef DLT_FDDI
        {DLT_FDDI, 13, 21, 16, "FDDI"},
#endif
#ifdef DLT_ATM_RFC1483
        {DLT_ATM_RFC1483, 0, 8, 3, "ATM_RFC1483"},
#endif
#ifdef DLT_RAW
        {DLT_RAW, -1, 0, 0, "RAW"},
#endif
#ifdef DLT_SLIP_BSDOS
        {DLT_SLIP_BSDOS, -1, 24, 24, "SLIP_BSDOS"},
#endif
#ifdef DLT_PPP_BSDOS
        {DLT_PPP_BSDOS, 5, 24, 24, "PPP_BSDOS"},
#endif
#ifdef DLT_ATM_CLIP
        {DLT_ATM_CLIP, 0, 8, 3, "ATM_CLIP"},
#endif
#ifdef DLT_PPP_SERIAL
        {DLT_PPP_SERIAL, 2, 4, 4, "PPP_SERIAL"},
#endif
#ifdef DLT_PPP_ETHER
        {DLT_PPP_ETHER, 6, 8, 8, "PPP_ETHER"},
#endif
#ifdef DLT_C_HDLC
        {DLT_C_HDLC, 2, 4, 4, "C_HDLC"},
#endif
#ifdef DLT_IEEE802_11
        {DLT_IEEE802_11, 24, 32, 27, "IEEE802_11"},
#endif
#ifdef DLT_LOOP
        {DLT_LOOP, 0, 4, 4, "LOOP"},
#endif
#ifdef DLT_LINUX_SLL
        {DLT_LINUX_SLL, 14, 16, 16, "LINUX_SLL"},
#endif
#ifdef DLT_LTALK
        {DLT_LTALK, -1, 0, 0, "LTALK"},
#endif
#ifdef DLT_PRISM_HEADER
        {DLT_PRISM_HEADER, 144 + 24, 144 + 30, 144 + 27, "PRISM_HEADER"},
#endif
#ifdef DLT_IP_OVER_FC
        {DLT_IP_OVER_FC, 16, 24, 19, "IP_OVER_FC"},
#endif
#ifdef DLT_SUNATM
        {DLT_SUNATM, 4, 4 + 8, 4 + 3, "SUNATM"},
#endif
#ifdef DLT_ARCNET_LINUX
        {DLT_ARCNET_LINUX, 4, 8, 8, "ARCNET_LINUX"},
#endif
#ifdef DLT_ENC
        {DLT_ENC, 0, 12, 12, "ENC"},
#endif
#ifdef DLT_FRELAY
        {DLT_FRELAY, -1, 0, 0, "FRELAY"},
#endif
#ifdef DLT_IEEE802_11_RADIO
        {DLT_IEEE802_11_RADIO, 64 + 24, 64 + 32, 64 + 27, "IEEE802_11_RADIO"},
#endif
#ifdef DLT_PFLOG
        {DLT_PFLOG, 0, 28, 28, "PFLOG"},
#endif
#ifdef DLT_LINUX_IRDA
        {DLT_LINUX_IRDA, -1, -1, -1, "LINUX_IRDA"},
#endif
#ifdef DLT_APPLE_IP_OVER_IEEE1394
        {DLT_APPLE_IP_OVER_IEEE1394, 16, 18, 0, "APPLE_IP_OVER_IEEE1394"},
#endif
#ifdef DLT_IEEE802_11_RADIO_AVS
        {DLT_IEEE802_11_RADIO_AVS, 64 + 24, 64 + 32, 64 + 27, "IEEE802_11_RADIO_AVS"},
#endif
#ifdef DLT_PFSYNC
        {DLT_PFSYNC, -1, 4, 4, "PFSYNC"},
#endif
        {-1, -1, -1, -1, "UNKNOWN"}
};
	
#endif
