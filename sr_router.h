/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define ICMP_TTL 64
#define PACKET_DUMP_SIZE 1024

#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_DEST_UNREACHABLE 3
#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_TIME_EXCEEDED 11

#define ICMP_CODE_ECHO_REPLY 0
#define ICMP_CODE_NET_UNREACHABLE 0
#define ICMP_CODE_HOST_UNREACHABLE 1
#define ICMP_CODE_PORT_UNREACHABLE 3
#define ICMP_CODE_TIME_EXCEEDED 0

#define ETHERNET_HEADER_CHECK 0
#define IP_HEADER_CHECK 1
#define ICMP_HEADER_CHECK 2
#define ARP_HEADER_CHECK 3

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_arpcache.c -- */
void sr_sendpacket_arprequest(struct sr_instance*, struct sr_arpreq*);
void sr_handle_arpreq(struct sr_instance*, struct sr_arpreq*);

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );
sr_ethernet_hdr_t *get_packet_ethernet_header(uint8_t *);
sr_ip_hdr_t *get_packet_ip_header(uint8_t *);
sr_icmp_hdr_t *get_packet_icmp_header(uint8_t *);
sr_icmp_t3_hdr_t *get_packet_icmp_t3_header(uint8_t *);
sr_arp_hdr_t *get_packet_arp_header(uint8_t *);
struct sr_rt *longest_prefix_match(struct sr_instance*, uint32_t);
int validate_length(int, unsigned char);
int validate_checksum(uint8_t *, int, unsigned char);
struct sr_rt *longest_prefix_match(struct sr_instance*, uint32_t);
void sr_forwardpacket_ip(struct sr_instance*, uint8_t *, unsigned int, char*);
void sr_sendpacket(struct sr_instance*, uint8_t*, unsigned int, struct sr_if*, struct sr_rt*);
void sr_sendpacket_ip(struct sr_instance*, uint8_t *, unsigned int, char*, struct sr_rt*);
void sr_sendpacket_icmp_echo_reply(struct sr_instance*, uint8_t *, unsigned int);
void sr_sendpacket_icmp_unreachable(struct sr_instance*, uint8_t *, unsigned int, uint8_t);
void sr_sendpacket_icmp_time_exceeded(struct sr_instance*, uint8_t *, unsigned int, char*);
void sr_handlepacket_icmp(struct sr_instance*, uint8_t *, unsigned int);
void sr_handlepacket_ip(struct sr_instance*, uint8_t *, unsigned int, char*);
void sr_handlepacket_arp_request(struct sr_instance*, uint8_t *, unsigned int, char*);
void sr_handlepacket_arp_reply(struct sr_instance*, uint8_t *, unsigned int);
void sr_handlepacket_arp(struct sr_instance*, uint8_t *, unsigned int, char*);

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

#endif /* SR_ROUTER_H */
