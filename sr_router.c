/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(
    struct sr_instance* sr,
    uint8_t * packet/* lent */,
    unsigned int len,
    char* interface/* lent */){
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);
    printf("*** -> Received packet of length %d \n",len);

    /* fill in code here */
  
    /*sanity check ethernet frame header*/ 
    if (!validate_length(len, ETHERNET_HEADER_CHECK)){
        return;
    }

    /*separate handlers for IP and ARP packets*/
    if (ethertype(packet) == ethertype_ip){
        sr_handlepacket_ip(sr, packet, len, interface);
    } else if (ethertype(packet) == ethertype_arp){
        sr_handlepacket_arp(sr, packet, len, interface);
    }

    return;
}

sr_ethernet_hdr_t* get_packet_ethernet_header(uint8_t * packet){
    return (sr_ethernet_hdr_t*) packet;
}

sr_ip_hdr_t* get_packet_ip_header(uint8_t * packet) {
    sr_ip_hdr_t *packet_ip_header = 
        (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    return packet_ip_header;   
}

sr_arp_hdr_t* get_packet_arp_header(uint8_t * packet) {
    sr_arp_hdr_t *packet_arp_header = 
        (sr_arp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
    return packet_arp_header;
}

sr_icmp_hdr_t* get_packet_icmp_header(uint8_t * packet){
    sr_icmp_hdr_t *packet_icmp_header = 
        (sr_icmp_hdr_t*) (packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
    return packet_icmp_header;
}

sr_icmp_t3_hdr_t* get_packet_icmp_t3_header(uint8_t * packet){
    sr_icmp_t3_hdr_t *packet_icmp_t3_header = 
        (sr_icmp_t3_hdr_t*) (packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
    return packet_icmp_t3_header;
}

struct sr_rt *longest_prefix_match(struct sr_instance* sr, uint32_t ip_address){
    struct sr_rt *rt_node;
    struct sr_rt *longest_matching_prefix = NULL;

    /*check all nodes in the routing table for the longest matching prefix of 'ip_address'*/
    for(rt_node = sr->routing_table; rt_node; rt_node = rt_node->next){
        /*check if there's a need to update the current longest match*/
        if ((ip_address & rt_node->mask.s_addr) == (rt_node->dest.s_addr & rt_node->mask.s_addr) &&
            (!longest_matching_prefix || longest_matching_prefix->mask.s_addr < rt_node->mask.s_addr)){
            longest_matching_prefix = rt_node;
        }
    }

    printf("*** longest matching prefix: %.32s\n", longest_matching_prefix->interface);
    return longest_matching_prefix;
}

int validate_length(int len, unsigned char check_type){
    int expected_len = 0;

    /*size sanity checks on all headers we'll be handling*/
    if (check_type == ETHERNET_HEADER_CHECK) {
        expected_len = sizeof(sr_ethernet_hdr_t);
    } else if (check_type == IP_HEADER_CHECK){
        expected_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
    } else if (check_type == ICMP_HEADER_CHECK){
        expected_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
    } else if (check_type == ARP_HEADER_CHECK){
        expected_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    }
    printf("*** validating length, %d >= %d\n", len, expected_len);
    return len >= expected_len;
}

int validate_checksum(uint8_t * packet, int len, unsigned char check_type){
    
    unsigned char valid = 0;

    /* sanity check for checksums of IP and ICMP packets*/
    /* making sure to set sum to 0 before calculating actual checksum*/
    if (check_type == IP_HEADER_CHECK) {
        sr_ip_hdr_t *packet_ip_header = get_packet_ip_header(packet);
        uint16_t checksum_ip = packet_ip_header->ip_sum;
        packet_ip_header->ip_sum = 0;
        printf("*** checksums ip: %d, %d\n", cksum(packet_ip_header, len), checksum_ip);
        valid = cksum(packet_ip_header, len) == checksum_ip;
        packet_ip_header->ip_sum = checksum_ip;
    } else if (check_type == ICMP_HEADER_CHECK) {
        sr_icmp_hdr_t *packet_icmp_header = get_packet_icmp_header(packet);
        uint16_t checksum_icmp = packet_icmp_header->icmp_sum;
        packet_icmp_header->icmp_sum = 0;
        printf("*** checksums icmp: %d, %d\n", cksum(packet_icmp_header, len), checksum_icmp);
        valid = cksum(packet_icmp_header, len) == checksum_icmp;
        packet_icmp_header->icmp_sum = checksum_icmp;
    }

    /*returning whether expected and actual checksum values match*/
    return valid;
}

void sr_forwardpacket_ip(
    struct sr_instance* sr,
    uint8_t * packet,
    unsigned int len,
    char* interface){
    
    printf("*** forwarding packet\n");
    sr_ip_hdr_t *packet_ip_header = get_packet_ip_header(packet);
   
    /*update ttl*/ 
    packet_ip_header->ip_ttl--;
    if (packet_ip_header->ip_ttl <= 0){
        printf("***     packet ttl hit 0\n");
        sr_sendpacket_icmp_time_exceeded(sr, packet, len, interface);
        return;
    }

    /*find next hop to send the packet to*/
    struct sr_rt *forwardpacket_rt = longest_prefix_match(sr, packet_ip_header->ip_dst);
    if (!forwardpacket_rt){
        sr_sendpacket_icmp_unreachable(sr, packet, len, ICMP_CODE_NET_UNREACHABLE);
        return;
    }
    
    struct sr_if *rt_interface = sr_get_interface(sr, forwardpacket_rt->interface);

    /*update checksum*/
    packet_ip_header->ip_sum = 0;
    packet_ip_header->ip_sum = cksum(packet_ip_header, sizeof(sr_ip_hdr_t));

    /*send the updated packet*/
    sr_sendpacket(sr, packet, len, rt_interface, forwardpacket_rt);
    
}

void sr_sendpacket(
    struct sr_instance* sr,
    uint8_t * packet,
    unsigned int len,
    struct sr_if* interface,
    struct sr_rt* routing_table){

    struct in_addr gateway = routing_table->gw;
    struct sr_arpentry *responsepacket_arpentry = sr_arpcache_lookup(&sr->cache, gateway.s_addr);
    printf("*** sending packet\n");
    sr_ethernet_hdr_t *packet_ethernet_header = get_packet_ethernet_header(packet);

    /*send arp request if destination IP is cached*/
    if(!responsepacket_arpentry){
        struct sr_arpreq *arprequest = sr_arpcache_queuereq(&sr->cache, gateway.s_addr, packet, len, interface->name);
        sr_handle_arpreq(sr, arprequest);
        return;
    }

    /*update ethernet header's destination and host mac addresses before sending*/
    memcpy(packet_ethernet_header->ether_dhost, responsepacket_arpentry->mac, ETHER_ADDR_LEN);
    memcpy(packet_ethernet_header->ether_shost, interface->addr, ETHER_ADDR_LEN); 
    sr_send_packet(sr, packet, len, interface->name);

    /*remember to free memory after calling sr_arpcache_lookup*/
    free(responsepacket_arpentry);
}

void sr_sendpacket_icmp_echo_reply(
    struct sr_instance* sr,
    uint8_t * packet,
    unsigned int len){
    printf("*** sending icmp echo reply\n");
    sr_ip_hdr_t *packet_ip_header = get_packet_ip_header(packet);
     
    /*create packet to echo back*/ 
    uint8_t *responsepacket = malloc(len);
    sr_ip_hdr_t *responsepacket_ip_header = get_packet_ip_header(responsepacket);
    sr_icmp_hdr_t *responsepacket_icmp_header = get_packet_icmp_header(responsepacket);
    memcpy(responsepacket, packet, len);
    
    /*find next hop for the source address we want to reply to*/
    struct sr_rt *responsepacket_rt = longest_prefix_match(sr, packet_ip_header->ip_src);
    struct sr_if *rt_interface = sr_get_interface(sr, responsepacket_rt->interface);        

    /*update IP header*/
    responsepacket_ip_header->ip_src = packet_ip_header->ip_dst;    
    responsepacket_ip_header->ip_dst = packet_ip_header->ip_src;
    responsepacket_ip_header->ip_sum = 0;
    responsepacket_ip_header->ip_sum = cksum(responsepacket_ip_header, sizeof(sr_ip_hdr_t));

    /*update ICMP header*/
    responsepacket_icmp_header->icmp_type = ICMP_TYPE_ECHO_REPLY;
    responsepacket_icmp_header->icmp_code = ICMP_CODE_ECHO_REPLY;
    responsepacket_icmp_header->icmp_sum = 0;
    unsigned int len_icmp = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t); 
    responsepacket_icmp_header->icmp_sum = cksum(responsepacket_icmp_header, len_icmp);

    /*send then free the newly created packet*/
    sr_sendpacket(sr, responsepacket, len, rt_interface, responsepacket_rt);
    free(responsepacket);

}

void sr_sendpacket_icmp_unreachable(
    struct sr_instance* sr,
    uint8_t * packet,
    unsigned int len,
    uint8_t code){
    printf("*** sending icmp unreachable\n");
    sr_ip_hdr_t *packet_ip_header = get_packet_ip_header(packet);
    len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    
    /*create a type 3 ICMP packet*/
    uint8_t *responsepacket = malloc(len);
    sr_ethernet_hdr_t *responsepacket_ethernet_header = get_packet_ethernet_header(responsepacket);
    sr_ip_hdr_t *responsepacket_ip_header = get_packet_ip_header(responsepacket);
    sr_icmp_t3_hdr_t *responsepacket_icmp_t3_header = get_packet_icmp_t3_header(responsepacket);

    /*find next hop for the source address we want to reply to*/
    struct sr_rt *responsepacket_rt = longest_prefix_match(sr, packet_ip_header->ip_src);
    struct sr_if *rt_interface = sr_get_interface(sr, responsepacket_rt->interface);        

    /*update ethernet header information*/
    responsepacket_ethernet_header->ether_type = htons(ethertype_ip);

    /*update IP header information to send back*/
    memcpy(responsepacket_ip_header, packet_ip_header, sizeof(sr_ip_hdr_t));
    responsepacket_ip_header->ip_tos = 0;
    responsepacket_ip_header->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    responsepacket_ip_header->ip_id = htons(0);
    responsepacket_ip_header->ip_off = htons(IP_DF);
    responsepacket_ip_header->ip_ttl = ICMP_TTL;
    responsepacket_ip_header->ip_p = ip_protocol_icmp;
    responsepacket_ip_header->ip_src = packet_ip_header->ip_dst;    
    responsepacket_ip_header->ip_dst = packet_ip_header->ip_src;
    responsepacket_ip_header->ip_sum = 0;
    responsepacket_ip_header->ip_sum = cksum(responsepacket_ip_header, sizeof(sr_ip_hdr_t));

    /*update ICMP header information for dest/host/net unreachable reply*/
    responsepacket_icmp_t3_header->icmp_type = ICMP_TYPE_DEST_UNREACHABLE;
    responsepacket_icmp_t3_header->icmp_code = code;
    responsepacket_icmp_t3_header->unused = htons(0);
    responsepacket_icmp_t3_header->next_mtu = htons(0);
    memcpy(responsepacket_icmp_t3_header->data, packet_ip_header, ICMP_DATA_SIZE); 
    responsepacket_icmp_t3_header->icmp_sum = 0;
    responsepacket_icmp_t3_header->icmp_sum = cksum(responsepacket_icmp_t3_header, sizeof(sr_icmp_t3_hdr_t)); 

    /*send then free the newly created packet*/
    sr_sendpacket(sr, responsepacket, len, rt_interface, responsepacket_rt);
    free(responsepacket);
}

void sr_sendpacket_icmp_time_exceeded(
    struct sr_instance* sr,
    uint8_t * packet,
    unsigned int len,
    char *interface){
    printf("*** sending icmp time exceeded\n");
    sr_ip_hdr_t *packet_ip_header = get_packet_ip_header(packet);
    len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    
    /*create type 11 ICMP packet (same structure as type 3)*/
    uint8_t *responsepacket = malloc(len);
    sr_ethernet_hdr_t *responsepacket_ethernet_header = get_packet_ethernet_header(responsepacket);
    sr_ip_hdr_t *responsepacket_ip_header = get_packet_ip_header(responsepacket);
    sr_icmp_t3_hdr_t *responsepacket_icmp_t3_header = get_packet_icmp_t3_header(responsepacket);

    /*find next hop for the source address we want to reply to*/
    struct sr_rt *responsepacket_rt = longest_prefix_match(sr, packet_ip_header->ip_src);
    struct sr_if *rt_interface = sr_get_interface(sr, responsepacket_rt->interface);        

    struct sr_if *interface_in = sr_get_interface(sr, interface);

    /*update ethernet header information*/
    responsepacket_ethernet_header->ether_type = htons(ethertype_ip);

    /*update IP header information to send back*/
    memcpy(responsepacket_ip_header, packet_ip_header, sizeof(sr_ip_hdr_t));
    responsepacket_ip_header->ip_tos = 0;
    responsepacket_ip_header->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    responsepacket_ip_header->ip_id = htons(0);
    responsepacket_ip_header->ip_off = htons(IP_DF);
    responsepacket_ip_header->ip_ttl = ICMP_TTL;
    responsepacket_ip_header->ip_p = ip_protocol_icmp;
    responsepacket_ip_header->ip_src = interface_in->ip;
    responsepacket_ip_header->ip_dst = packet_ip_header->ip_src;
    responsepacket_ip_header->ip_sum = 0;
    responsepacket_ip_header->ip_sum = cksum(responsepacket_ip_header, sizeof(sr_ip_hdr_t));

    /*update ICMP header information for ttl exceeded*/
    responsepacket_icmp_t3_header->icmp_type = ICMP_TYPE_TIME_EXCEEDED;
    responsepacket_icmp_t3_header->icmp_code = ICMP_CODE_TIME_EXCEEDED; 
    responsepacket_icmp_t3_header->unused = htons(0);
    responsepacket_icmp_t3_header->next_mtu = htons(0);
    memcpy(responsepacket_icmp_t3_header->data, packet_ip_header, ICMP_DATA_SIZE); 
    responsepacket_icmp_t3_header->icmp_sum = 0;
    responsepacket_icmp_t3_header->icmp_sum = cksum(responsepacket_icmp_t3_header, sizeof(sr_icmp_t3_hdr_t)); 

    /*send then free the newly created packet*/
    sr_sendpacket(sr, responsepacket, len, rt_interface, responsepacket_rt);
    free(responsepacket);
}

void sr_handlepacket_icmp(
    struct sr_instance* sr,
    uint8_t * packet,
    unsigned int len){
    printf("*** handling icmp packet, len: %d, %lu\n", len, sizeof(sr_icmp_t3_hdr_t)); 
    sr_ip_hdr_t *packet_ip_header = get_packet_ip_header(packet);

    printf("*** packet ip protocol: %d, %d\n", packet_ip_header->ip_p, ip_protocol_icmp);

    /*only ICMP packets we have to handle are echo replies*/
    /*return destination unreachable for tcp/udp packets*/ 
    if (packet_ip_header->ip_p == ip_protocol_icmp){
        printf("*** icmp echo received\n");
        /*sanity check if length and checksum are valid before replying*/
        if (!validate_checksum(packet, len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t), ICMP_HEADER_CHECK) ||
            !validate_length(len, ICMP_HEADER_CHECK)){
            printf("*** icmp validation failed\n");
            return;
        }
        sr_sendpacket_icmp_echo_reply(sr, packet, len);
    } else {
        printf("*** udp/tcp received\n");
        sr_sendpacket_icmp_unreachable(sr, packet, len, ICMP_CODE_PORT_UNREACHABLE);
    }
}

void sr_handlepacket_ip(
    struct sr_instance* sr,
    uint8_t * packet,
    unsigned int len,
    char* interface){
    printf("*** handling ip packet\n");        
   
     /*sanity check ip packet length and checksum*/
    if (!validate_length(len, IP_HEADER_CHECK)){
        return;
    }
    if (!validate_checksum(packet, sizeof(sr_ip_hdr_t), IP_HEADER_CHECK) ||
        !validate_length(len, IP_HEADER_CHECK)){
        return;
    }

    sr_ip_hdr_t *packet_ip_header = get_packet_ip_header(packet);
    printf("***     ip packet ttl: %d\n", packet_ip_header->ip_ttl);

    /*if packet's destination is this router, packet will be icmp/tcp/udp message*/
    struct sr_if *destination_interface;
    for (destination_interface = sr->if_list; destination_interface;
         destination_interface = destination_interface->next){
        if (packet_ip_header->ip_dst == destination_interface->ip){
            sr_handlepacket_icmp(sr, packet, len);
            return;
        }
    }
    /*otherwise forward the packet on*/
    sr_forwardpacket_ip(sr, packet, len, interface);
}

void sr_handlepacket_arp_request(
    struct sr_instance* sr,
    uint8_t * packet,
    unsigned int len,
    char* interface){
    printf("*** received arp request\n");
    sr_ethernet_hdr_t *packet_ethernet_header = get_packet_ethernet_header(packet);
    sr_arp_hdr_t *packet_arp_header = get_packet_arp_header(packet);
    len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);

    /*create ARP packet for ARP reply*/
    uint8_t *responsepacket = malloc(len);
    sr_ethernet_hdr_t *responsepacket_ethernet_header = get_packet_ethernet_header(responsepacket);
    sr_arp_hdr_t *responsepacket_arp_header = get_packet_arp_header(responsepacket);
       
    struct sr_if *interface_in = sr_get_interface(sr, interface);

    /*update ethernet header and its source and destination information to reply with*/
    memcpy(responsepacket_ethernet_header->ether_shost, 
           interface_in->addr, ETHER_ADDR_LEN);
    memcpy(responsepacket_ethernet_header->ether_dhost,
           packet_ethernet_header->ether_shost, ETHER_ADDR_LEN);
    responsepacket_ethernet_header->ether_type = htons(ethertype_arp);

    /*copy and update ARP header for a reply to the given request*/
    responsepacket_arp_header->ar_hrd = packet_arp_header->ar_hrd;
    responsepacket_arp_header->ar_pro = packet_arp_header->ar_pro;
    responsepacket_arp_header->ar_hln = packet_arp_header->ar_hln;
    responsepacket_arp_header->ar_pln = packet_arp_header->ar_pln;
    responsepacket_arp_header->ar_op = htons(arp_op_reply);
    memcpy(responsepacket_arp_header->ar_sha, interface_in->addr, ETHER_ADDR_LEN);
    responsepacket_arp_header->ar_sip = interface_in->ip;
    memcpy(responsepacket_arp_header->ar_tha, packet_arp_header->ar_sha, ETHER_ADDR_LEN);
    responsepacket_arp_header->ar_tip = packet_arp_header->ar_sip;

    /*send then free the newly created packet*/
    sr_send_packet(sr, responsepacket, len, interface_in->name);
    free(responsepacket);
}

void sr_handlepacket_arp_reply(
    struct sr_instance* sr,
    uint8_t * packet,
    unsigned int len){
   
    sr_arp_hdr_t *packet_arp_header = get_packet_arp_header(packet);
    
    sr_ethernet_hdr_t *packet_ethernet_header; 
    struct sr_if *interface_in;

    /*cache the ARP reply*/
    struct sr_arpreq *arprequest_cached_entry =
            sr_arpcache_insert(&sr->cache, packet_arp_header->ar_sha, packet_arp_header->ar_sip);
    printf("*** handling arp reply\n"); 
    /*check if reply could be cached*/
    if (!arprequest_cached_entry){
        return;           
    }

    /*send off all packets waiting on this reply*/
    struct sr_packet *arprequest_packet;
    for(arprequest_packet = arprequest_cached_entry->packets; arprequest_packet; 
        arprequest_packet = arprequest_packet->next){
       
        packet_ethernet_header = get_packet_ethernet_header(arprequest_packet->buf); 
        interface_in = sr_get_interface(sr, arprequest_packet->iface);

        /*update ethernet header before sending off each packet*/
        memcpy(packet_ethernet_header->ether_shost, interface_in->addr, ETHER_ADDR_LEN);
        memcpy(packet_ethernet_header->ether_dhost, packet_arp_header->ar_sha, ETHER_ADDR_LEN);
        sr_send_packet(sr, arprequest_packet->buf, arprequest_packet->len, arprequest_packet->iface);
    }
    
    /*destroy cached reply after we're done*/
    sr_arpreq_destroy(&sr->cache, arprequest_cached_entry);
}

void sr_handlepacket_arp(
    struct sr_instance* sr,
    uint8_t * packet,
    unsigned int len,
    char* interface){

    /*sanity check on length for ARP packet*/
    if (!validate_length(len, ARP_HEADER_CHECK)){
        return;
    }

    sr_arp_hdr_t *packet_arp_header = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
    
    uint16_t packet_opcode = ntohs(packet_arp_header->ar_op);
    printf("*** arp header opcode = %d\n", packet_opcode);

    /*separate handlers for ARP requests and replies*/
    if (packet_opcode == arp_op_request){
        sr_handlepacket_arp_request(sr, packet, len, interface);
    } else if (packet_opcode == arp_op_reply){
        sr_handlepacket_arp_reply(sr, packet, len);
    }
}

void sr_sendpacket_arprequest(struct sr_instance *sr, struct sr_arpreq *arprequest){
    int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);

    /*create ARP packet for an ARP request*/
    uint8_t *responsepacket = malloc(len);
    sr_ethernet_hdr_t *responsepacket_ethernet_header = get_packet_ethernet_header(responsepacket);
    sr_arp_hdr_t *responsepacket_arp_header = get_packet_arp_header(responsepacket);
    
    printf("*** sending packet arprequest\n");

    struct sr_packet *arprequest_packet = arprequest->packets;
    struct sr_if *arprequest_interface = sr_get_interface(sr, arprequest_packet->iface);
    
    /*update ethernet header information, remembering to zero out destination address*/
    memcpy(responsepacket_ethernet_header->ether_shost, arprequest_interface->addr, ETHER_ADDR_LEN);
    memset(responsepacket_ethernet_header->ether_dhost, 0xff, ETHER_ADDR_LEN);
    responsepacket_ethernet_header->ether_type = htons(ethertype_arp);

    /*update ARP header information, remembering to zero out target's address*/
    responsepacket_arp_header->ar_hrd = htons(arp_hrd_ethernet);
    responsepacket_arp_header->ar_pro = htons(ethertype_ip);
    responsepacket_arp_header->ar_hln = ETHER_ADDR_LEN;
    responsepacket_arp_header->ar_pln = sizeof(ethertype_ip);
    responsepacket_arp_header->ar_op = htons(arp_op_request);
    memcpy(responsepacket_arp_header->ar_sha, arprequest_interface->addr, ETHER_ADDR_LEN);
    responsepacket_arp_header->ar_sip = arprequest_interface->ip; 
    memset(responsepacket_arp_header->ar_tha, 0xff, ETHER_ADDR_LEN);
    responsepacket_arp_header->ar_tip = arprequest->ip;
    
    /*send then free the newly created packet*/
    sr_send_packet(sr, responsepacket, len, arprequest_interface->name);
    free(responsepacket);
}

void sr_handle_arpreq(struct sr_instance *sr, struct sr_arpreq *arprequest){
    printf("*** handling arprequest\n");
    /*requests are sent once a second*/
    if (difftime(time(0), arprequest->sent) >= 1.0){
        printf("*** times sent: %d\n", arprequest->times_sent);

        /*send an ARP request until 5 failed attempts have been made*/
        /*send ICMP unreachable if that's the case*/
        if (arprequest->times_sent >= 5){
            struct sr_packet *arprequest_packet;
            for(arprequest_packet = arprequest->packets; arprequest_packet;
                arprequest_packet = arprequest_packet->next){

                sr_sendpacket_icmp_unreachable(sr, arprequest_packet->buf, 
                                               arprequest_packet->len, 
                                               ICMP_CODE_HOST_UNREACHABLE);
            }
            /*destroy the cached entry for the failed ARP request*/
            sr_arpreq_destroy(&sr->cache, arprequest);
        } else {
            sr_sendpacket_arprequest(sr, arprequest);
            arprequest->sent = time(0);
            arprequest->times_sent++;
        }
    }
}
