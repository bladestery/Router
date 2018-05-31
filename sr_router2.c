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
#include <sys/time.h>

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

enum options {
    Record_Route = 7,
    Strict_Source_Route = 137,
    Time_Stamp = 68,
    Loose_Source_Route = 131,
    Traceroute = 82,
};

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

void sr_handle_icmp(struct sr_instance *sr, sr_ip_hdr_t *iph_cpy, char* interface, uint8_t type, uint8_t code, uint32_t raddr, uint8_t point, struct sr_if *outbound, sr_ip_tr_hdr_t *ip_tr)
{
    uint32_t *data;
    sr_ip_hdr_t *packet;
    
    if (type == 30) {
        if ((packet = (sr_ip_hdr_t *) calloc(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_tr_hdr_t), 1)) == NULL)
            fprintf(stderr, "calloc failed.\n");
        packet->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_tr_hdr_t));
        packet->ip_dst = ip_tr->tr_origin;
    }
    else {
        if ((packet = (sr_ip_hdr_t *) calloc(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), 1)) == NULL)
            fprintf(stderr, "calloc failed.\n");
        packet->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        packet->ip_dst = iph_cpy->ip_src;
    }
    packet->ip_hl = 5;
    packet->ip_v = iph_cpy->ip_v;
    packet->ip_tos = iph_cpy->ip_tos;
    packet->ip_ttl = 64;
    packet->ip_p = ip_protocol_icmp;
    packet->ip_src = htonl(raddr);
    packet->ip_sum = htons(cksum(packet, sizeof(sr_ip_hdr_t)));
    
    
    if (type == 30) {
        sr_icmp_tr_hdr_t *tr;
        tr = (sr_icmp_tr_hdr_t *) (packet + 1);
        
        tr->tr_type = type;
        tr->tr_code = code;
        
        tr->tr_id = ip_tr->tr_id;
        tr->tr_ohc = ip_tr->tr_ohc;
        tr->tr_rhc = ip_tr->tr_rhc;
        
        if (code == 0) {
            tr->tr_spd = htonl(outbound->speed);
            tr->tr_mtu = htonl(1500); // EDIT LATER
        }
        
        tr->tr_sum = htons(cksum(tr, sizeof(sr_icmp_tr_hdr_t)));
        sr_send_packet(sr, (uint8_t *) packet, sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_tr_hdr_t ), interface);
    }
    else {
        uint8_t *error;
        sr_icmp_t3_hdr_t *icmp;
        icmp = (sr_icmp_t3_hdr_t *) (packet + 1);
        
        icmp->icmp_type = type;
        icmp->icmp_code = code;
        memcpy(icmp->data, iph_cpy, sizeof(sr_ip_hdr_t));
        data = ((uint8_t *) iph_cpy) + 4 * iph_cpy->ip_hl;
        memcpy(icmp->data + sizeof(sr_ip_hdr_t), data, 2 * sizeof(uint32_t));
        
        if (type == 12) {
            error = ((uint8_t *) icmp) + 4;
            *error = point;
        }
        
        icmp->icmp_sum = htons(cksum(icmp, sizeof(sr_icmp_t3_hdr_t)));
        sr_send_packet(sr, (uint8_t *) packet, sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface);
    }
    
    free(packet);
}

void sr_handle_ip(struct sr_instance *sr, sr_ethernet_hdr_t *ethh, char* interface)
{
    sr_ip_hdr_t *iph = (sr_ip_hdr_t *) (ethh + 1);
    short hip_head, hip_sum, hip_ttl, hip_dst, hicmp_sum, hip_len;
    size_t minlength = sizeof(sr_ip_hdr_t);
    int ip_match = 0;
    struct sr_if* in_interface;
    if ((in_interface = sr_get_interface(sr, interface)) == 0) {
        fprintf(stderr, "Unable to find interface.\n");
    }
    
    struct sr_if *temp;
    uint32_t raddr;
    for (temp = sr->if_list; temp == NULL; temp = temp->next) {
        if ((raddr = temp->ip) == ntohl(iph->ip_p)) {
            ip_match = 1;
            break;
        }
    }
    
    if (!ip_match) {
        raddr = in_interface->ip;
    }
    
    hip_head = 4 * ntohs(iph->ip_hl);
    if (hip_head < minlength) {
        fprintf(stderr, "NOT a valid IP packet: invalid length.\n");
        return;
    }
    
    hip_sum = ntohs(iph->ip_sum);
    if (hip_sum == cksum(iph, hip_head)) {
        hip_ttl = iph->ip_ttl;
        if (hip_ttl > 0) {
            sr_ip_hdr_t *iph_cpy;
            if ((iph_cpy = malloc(hip_head + 2 * sizeof(uint32_t))) == NULL) {
                fprintf(stderr, "malloc failed.\n");
                return;
            }
            else
                memcpy(iph_cpy, iph, hip_head + 2 * sizeof(uint32_t));
            
            hip_dst = ntohl(iph->ip_dst);
            if (iph->ip_p == ip_protocol_icmp && hip_dst == raddr) {
                sr_icmp_hdr_t *ich = (sr_icmp_hdr_t *) (((uint8_t *) iph) + hip_head);
                
                hicmp_sum = ntohs(ich->icmp_sum);
                hip_len = ntohs(iph->ip_len);
                if (hicmp_sum == cksum(ich, hip_len - hip_head)) {
                    if (ich->icmp_code == 8) {
                        ich->icmp_code = 0;
                        ich->icmp_sum = 0;
                        ich->icmp_sum = htons(cksum(ich, hip_len - hip_head));
                        
                        iph->ip_dst = iph->ip_dst ^ iph->ip_src;
                        iph->ip_src = iph->ip_dst ^ iph->ip_src;
                        iph->ip_dst = iph->ip_dst ^ iph->ip_src;
                        
                        uint8_t *opt;
                        if (iph->ip_hl > 5) {
                            opt = (uint8_t *) (iph + 1);
                            
                            do {
                                /* maybe this is dangerous */
                                /*
                                 if (*opt == 0) {
                                 break;
                                 }
                                 */
                                if (*opt == Record_Route) {
                                    uint8_t *len, *point, *pointer;
                                    
                                    len = opt + 1;
                                    point = len + 1;
                                    pointer = *point + opt;
                                    opt = opt + *len;
                                    
                                    if (*point > (*len) - sizeof(uint32_t *)) {
                                        if (opt == pointer) {
                                            sr_handle_icmp(sr, iph_cpy, interface, 12, 0, raddr, *point, NULL, NULL);
                                            continue;
                                        }
                                        else {
                                            sr_handle_icmp(sr, iph_cpy, interface, 12, 0, raddr, *point, NULL, NULL);
                                            free(iph_cpy);
                                            return;
                                        }
                                    }
                                    else {
                                        *pointer = htonl(raddr);
                                        *point += sizeof(uint32_t *);
                                        continue;
                                    }
                                }
                                
                                else if (*opt == Time_Stamp) {
                                    uint8_t *len, *point, *det, *pointer;
                                    uint8_t flag, oflow;
                                    
                                    len = opt + 1;
                                    point = len + 1;
                                    pointer = opt + *point;
                                    det = opt + 3;
                                    
                                    /* masking to access 4 bit entries */
                                    flag = *det & 15;
                                    oflow = (*det & 140) >> 4;
                                    opt = opt + *len;
                                    
                                    if (oflow == 15) {
                                        sr_handle_icmp(sr, iph_cpy, interface, 12, 0, raddr, sizeof(uint8_t) * 3, NULL, NULL);
                                        free(iph_cpy);
                                        return;
                                    }
                                    else {
                                        if (flag == 0) {
                                            if (*point > (*len) - sizeof(uint32_t *)) {
                                                if (opt == pointer) {
                                                    sr_handle_icmp(sr, iph_cpy, interface, 12, 0, raddr, *point, NULL, NULL);
                                                    *det += 16; /* 1<<4 */
                                                    continue;
                                                }
                                                else {
                                                    sr_handle_icmp(sr, iph_cpy, interface, 12, 0, raddr, *point, NULL, NULL);
                                                    free(iph_cpy);
                                                    return;
                                                }
                                            }
                                            else {
                                                int time;
                                                struct timeval tv;
                                                
                                                gettimeofday(&tv, NULL);
                                                time = tv.tv_usec *1000;
                                                
                                                *pointer = htonl(time);
                                                *point += sizeof(uint32_t *);
                                                continue;
                                            }
                                        }
                                        else if (flag == 1) {
                                            if (*point > (*len) - 2 * sizeof(uint32_t *)) {
                                                if (opt == pointer) {
                                                    sr_handle_icmp(sr, iph_cpy, interface, 12, 0, raddr, *point, NULL, NULL);
                                                    *det += 16;
                                                    continue;
                                                }
                                                else {
                                                    sr_handle_icmp(sr, iph_cpy, interface, 12, 0, raddr, *point, NULL, NULL);
                                                    free(iph_cpy);
                                                    return;
                                                }
                                            }
                                            else {
                                                int time;
                                                struct timeval tv;
                                                
                                                gettimeofday(&tv, NULL);
                                                time = tv.tv_usec *1000;
                                                
                                                *pointer = htonl(raddr);
                                                pointer += sizeof(uint32_t *);
                                                *point += sizeof(uint32_t *);
                                                *pointer = htonl(time);
                                                *point += sizeof(uint32_t *);
                                                continue;
                                            }
                                        }
                                        else if (flag == 3) {
                                            if (*point > (*len) - sizeof(uint32_t *)) {
                                                if (opt == pointer) {
                                                    sr_handle_icmp(sr, iph_cpy, interface, 12, 0, raddr, *point, NULL, NULL);
                                                    continue;
                                                }
                                                else {
                                                    sr_handle_icmp(sr, iph_cpy, interface, 12, 0, raddr, *point, NULL, NULL);
                                                    free(iph_cpy);
                                                    return;
                                                }
                                            }
                                            else if (raddr == ntohl(*pointer)) {
                                                int time;
                                                struct timeval tv;
                                                
                                                gettimeofday(&tv, NULL);
                                                time = tv.tv_usec *1000;
                                                
                                                pointer += sizeof(uint32_t *);
                                                *pointer = htonl(time);
                                                *point += 2 * sizeof(uint32_t *);
                                                continue;
                                            }
                                            else {
                                                continue;
                                            }
                                        }
                                    }
                                }
                                
                                else if (*opt == Loose_Source_Route || *opt == Strict_Source_Route) {
                                    uint8_t *len, *point, *pointer;
                                    
                                    len = opt + 1;
                                    point = len +1;
                                    pointer = opt + *point;
                                    opt = opt + *len;
                                    
                                    if (*point > (*len) - sizeof(uint32_t *)) {
                                        if (opt == pointer) {
                                            continue;
                                        }
                                        else {
                                            sr_handle_icmp(sr, iph_cpy, interface, 12, 0, raddr, *point, NULL, NULL);
                                            continue;
                                        }
                                    }
                                    else {
                                        iph->ip_dst = *pointer;
                                        *point += sizeof(uint32_t *);
                                        continue;
                                    }
                                }
                                
                                else if (*opt == Traceroute) {
                                    sr_ip_tr_hdr_t *tr;
                                    tr = (sr_ip_tr_hdr_t *) opt;
                                    
                                    opt = opt + tr->tr_len;
                                    
                                    tr->tr_rhc = 0;
                                }
                                
                                opt++; /* intuitive? */
                            } while ((sr_icmp_hdr_t *) opt < ich); /* is this really correct */
                        }
                        
                        iph->ip_ttl = 64;
                        iph->ip_sum = 0;
                        iph->ip_sum = htons(cksum(iph, hip_head));
                        
                        sr_send_packet(sr, (uint8_t *) iph, hip_len, interface);
                        free(iph_cpy);
                    }
                    else if (ich->icmp_code == 30) {
                        /* traceroute icmp message */
                        fprintf(stderr, "Received ICMP traceroute message.\n");
                        free(iph_cpy);
                    }
                    else{
                        fprintf(stderr, "Dunno how to process this icmp code.\n");
                        free(iph_cpy);
                    }
                }
                else {
                    fprintf(stderr, "Invalid ICMP checksum.\n");
                    free(iph_cpy);
                }
            }
            else if ((iph->ip_p == ip_protocol_udp || iph->ip_p == ip_protocol_tcp)  && hip_dst == raddr) {
                sr_handle_icmp(sr, iph_cpy, interface, 3, 3, raddr, 0, NULL, NULL);
                free(iph_cpy);
            }
            else if (hip_dst == raddr) {
                fprintf(stderr, "Dropping ip packets destined to us. Not TCP/UDP.\n");
                /* might need to check for traceroute option, then drop if not traceroute */
                free(iph_cpy);
            }
            else { /* handle traceroute somewhere below when forward. what if the ip packet is destined for us (and also in the case with ip option trace route ) */
                struct sr_rt *entry, *match;
                struct sr_arpentry *arp;
                struct sr_if* out_interface;
                long plen = 0, len;
                char *diff;
                unsigned result;
                int j, has_traceroute = 0, to_origin = 0;
                
                uint8_t *opt;
                if (iph->ip_hl > 5) {
                    opt = (uint8_t *) (iph + 1);
                    
                    do {
                        /*maybe this is dangerous*/
                        /*
                         if (*opt == 0) {
                         break;
                         }
                         */
                        if (*opt == Traceroute) {
                            sr_ip_tr_hdr_t *tr;
                            tr = opt;
                            has_traceroute = 1;
                            
                            if (tr->tr_rhc == 0xFFFF)
                                tr->tr_ohc = htons(ntohs(tr->tr_ohc) + 1);
                            else {
                                tr->tr_rhc = htons(ntohs(tr->tr_rhc) + 1);
                                to_origin = 1;
                            }
                            
                            break;
                        }
                        opt++;
                    } while (opt - iph < hip_head); /* beware */
                    
                    iph->ip_ttl--;
                    iph->ip_sum = 0;
                    iph->ip_sum = htons(cksum(iph, hip_head));
                    
                    for (entry = sr->routing_table; entry != NULL; entry = entry->next) {
                        
                        /*    XORing sets result bit to 1 if ip_dst and
                         routing table node ip are different         */
                        result = entry->dest.s_addr ^ hip_dst;  /* maintain bits representation ???? */
                        
                        /*    convert result to string     */
                        char temp[8 * sizeof(result) + 1] = {0};
                        for (j = 0; j < (8 * sizeof(result) + 1); j++) {
                            temp[j] = (result << j) & (1 << (8*sizeof(unsigned int)-1)) ? '1' : '0';
                        }
                        
                        /*    find first difference       */
                        diff = strchr(temp, '1');
                        
                        /*    perfect match      */
                        if (diff == NULL) {
                            match = entry;
                            break;
                        }
                        else {  /*     assign match to entry if longer match      */
                            len = diff - temp;
                            if (len > plen) {
                                plen = len;
                                match = entry;
                            }
                        }
                    }
                    
                    if (match == NULL) {
                        if (has_traceroute ) {
                            if (!to_origin)
                                sr_handle_icmp(sr, iph_cpy, interface, 30, 1, raddr, 0, NULL, tr);
                        }
                        else
                            sr_handle_icmp(sr, iph_cpy, interface, 3, 0, raddr, 0, NULL, NULL);
                        
                        free(iph_cpy);
                    }
                    else {
                        if ((arp = sr_arpcache_lookup(sr->cache, htonl(match->dest))) == NULL) {
                            sr_arpreq* req;
                            /* handle arp requesting */
                            req = sr_arpcache_queuereq(sr->cache, htonl(match->dest), (uint8_t *) iph, hip_len, match->interface); //check byte ordering!
                            sr_handle_arp_req(sr, req);
                            free(iph_cpy);
                            return;
                        }
                        else
                            free(arp);
                        
                        if ((out_interface = sr_get_interface(sr, match->interface)) == 0) {
                            fprintf(stderr, "Unable to find interface.\n");
                        }
                        
                        if (has_traceroute)
                            sr_handle_icmp(sr, iph_cpy, interface, 30, 0, raddr, 0, out_interface, tr);
                        sr_send_packet(sr, (uint8_t *) iph, hip_len, out_interface->name);
                        free(iph_cpy);
                    }
                }
            }
            else {
                fprintf(stderr, "TTL = 0\n");
                sr_handle_icmp(sr, iph_cpy, interface, 11, 0, raddr, 0, NULL, NULL);
            }
        }
        else
            fprintf(stderr, "Invalid checksum.\n");
    }
    return;
}


void sr_handle_arp(struct sr_instance *sr, sr_ethernet_hdr_t *ethh, char* interface)
{
    sr_arp_hdr_t *arh = (sr_arp_hdr_t *) (ethh +1);
    int ip_match = 0;
    struct sr_if* in_interface;
    if ((in_interface = sr_get_interface(sr, interface)) == 0) {
        fprintf(stderr, "Unable to find interface.\n");
    }
    
    sr_if *temp;
    uint32_t raddr;
    for (temp = sr->if_list; temp == NULL; temp = temp->next) {
        if ((raddr = temp->ip) == ntohl(arh->ar_tip)) {
            ip_match = 1;
            break;
        }
    }
    
    if (!ip_match) {
        uint32_t raddr = in_interface->ip;
    }
    
    if (ntohs(arh->ar_op) == arp_op_request) {
        if (ntohl(arh->ar_tip) == raddr) {
            /*add to arp cache */
            sr_arpentry *arp, *temp_arp;
            int j;
            
            if ((arp = sr_arpcache_lookup(sr->cache, htonl(raddr)) == NULL)) {
                char temp_mac[ETHER_ADDR_LEN];
                for (int i = 0; i < ETHER_ADDR_LEN; i++) {
                    temp_mac[i] = arh->sha[ETHER_ADDR_LEN - 1 - i];
                }
                sr_arpcache_insert(sr->cache, temp_mac, arh->sip);
            }
            else {
                for (j = 0; sr->cache[j] == NULL || j == SR_ARPCACHE_SZ; j++) {
                    temp_arp = sr->cache[j];
                    if (arp->ip == temp_arp->ip) {
                        temp_arp->added = time(NULL);
                        break;
                    }
                }
                free(arp);
            }
            
            arh->ar_op = htons(arp_op_reply);
            memcpy(arh->ar_sha, arh->ar_tha, ETHER_ADDR_LEN);
            arh->ar_sip = arh->ar_sip ^ arh->ar_tip;
            arh->ar_tip = arh->ar_sip ^ arh->ar_tip;
            arh->ar_sip = arh->ar_sip ^ arh->ar_tip;
            
            for (int i = 0; i < ETHER_ADDR_LEN; i++) {
                arh->sha[i] = in_interface->addr[ETHER_ADDR_LEN - 1 - i];
            }
            
            sr_send_packet(sr, arh, sizeof(sr_arp_hdr_t), interface);
        }
    }
    
    else if (ntohs(arh->ar_op) == arp_op_reply) {
        sr_arpreq *entry;
        char temp_mac[ETHER_ADDR_LEN];
        
        for (int i = 0; i < ETHER_ADDR_LEN; i++) {
            temp_mac[i] = arh->sha[ETHER_ADDR_LEN - 1 - i];
        }
        entry = sr_arpcache_insert(sr->cache, temp_mac, arh->sip);
        
        if (entry == NULL) {
            fprintf(stderr, "no arprequest.\n");
        }
        else {
            sr_packet *packet;

            for (packet = entry->packets; packet == NULL; packet = packet->next) {
                sr_send_packet(sr, packet->buf, packet->len, packet->iface)
            }
            sr_arpreq_destroy(sr->cache, entry);
        }
    }  
}

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

void sr_handlepacket(struct sr_instance* sr,
                     uint8_t * packet/* lent */,
                     unsigned int len,
                     char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);
    
    printf("*** -> Received packet of length %d \n",len);
    
    /* fill in code here */
    
    /* sanity check */
    size_t minlength = sizeof(sr_ethernet_hdr_t);
    if (len < minlength) {
        fprintf(stderr, "NOT a valid packet: invalid length.\n");
        return;
    }
    
    /* Ethernet header */
    sr_ethernet_hdr_t *ethh = (sr_ethernet_hdr_t *) packet;
    uint16_t ether_type = ntohs(ethh->ether_type);
    if (ether_type == ethertype_ip) {
        sr_handle_ip(sr, ethh, interface);
    }
    else if (ether_type == ethertype_arp){
        sr_handle_arp(sr, ethh, interface);
    }
    
    
}/* end sr_ForwardPacket */

