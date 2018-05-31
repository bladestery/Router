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

/* handles sending ICMP packet */
void sr_handle_icmp(struct sr_instance *sr, sr_ethernet_hdr_t *ethh, struct sr_if *in_interface, uint8_t type, uint8_t code,
                    uint8_t point, struct sr_if *outbound, sr_ip_tr_hdr_t *ip_tr)
{
    sr_ethernet_hdr_t *temp;
    sr_ip_hdr_t *packet, *iph;
    
    iph = (sr_ip_hdr_t *) (ethh + 1);
    
    /* allocate memory for outgoing icmp packet according to type */
    if (type == 30) { /* traceroute message */
        if ((temp = (sr_ethernet_hdr_t *) calloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_tr_hdr_t), 1)) == NULL)
            fprintf(stderr, "calloc failed.\n");
        packet = (sr_ip_hdr_t *) (temp + 1);
        packet->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_tr_hdr_t));
        packet->ip_dst = ip_tr->tr_origin;
    }
    else { /* type 3 message */
        if ((temp = (sr_ethernet_hdr_t *) calloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), 1)) == NULL)
            fprintf(stderr, "calloc failed.\n");
        packet = (sr_ip_hdr_t *) (temp + 1);
        packet->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        packet->ip_dst = iph->ip_src;
    }
    
    temp->ether_type = htons(ethertype_ip);
    
    /* fill out remaining ip header fields */
    packet->ip_hl = 5;
    packet->ip_v = 4;
    packet->ip_tos = 0;
    packet->ip_id = htons(0);
    packet->ip_ttl = 64;
    packet->ip_off = htons(IP_DF);
    packet->ip_p = ip_protocol_icmp;
    packet->ip_src = in_interface->ip;
    packet->ip_sum = 0;
    packet->ip_sum = cksum(packet, sizeof(sr_ip_hdr_t));
    
    /* fill out icmp fields */
    if (type == 30) { /* traceroute */
        sr_icmp_tr_hdr_t *tr;
        tr = (sr_icmp_tr_hdr_t *) (packet + 1);
        
        tr->tr_type = type;
        tr->tr_code = code;
        tr->tr_id = ip_tr->tr_id;
        tr->tr_ohc = ip_tr->tr_ohc;
        tr->tr_rhc = ip_tr->tr_rhc;
        if (code == 0) {
            tr->tr_spd = htonl(outbound->speed);
            tr->tr_mtu = htonl(1500);
        }
        tr->tr_sum = cksum(tr, sizeof(sr_icmp_tr_hdr_t));
        
        struct sr_arpentry *arp;
        if ((arp = sr_arpcache_lookup(&sr->cache, packet->ip_dst)) == NULL) {
            struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, ip_tr->tr_origin, (uint8_t *)temp, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_tr_hdr_t), in_interface->name);
            req->interface = in_interface->name;
            sr_handle_arp_req(sr, req);
            return;
        }
        
        /* modify ethernet header: packet should be sent out on recieved interface */
        memcpy(temp->ether_dhost, arp->mac, ETHER_ADDR_LEN);
        memcpy(temp->ether_shost, in_interface->addr, ETHER_ADDR_LEN);

        sr_send_packet(sr, (uint8_t *) temp, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_tr_hdr_t), in_interface->name);
        free(arp);
    }
    else { /* type 3 icmp headers */
        /*uint8_t *error;*/
        sr_icmp_t3_hdr_t *icmp;
        icmp = (sr_icmp_t3_hdr_t *) (packet + 1);
        
        icmp->icmp_type = type;
        icmp->icmp_code = code;
        
        /* ip header w/o options and first 8 bytes of data are copied */
        memcpy(icmp->data, iph, sizeof(sr_ip_hdr_t) +  2 * sizeof(uint32_t));

        /* parameter problem, particularly in options of original packet
        if (type == 12) {
            error = ((uint8_t *) icmp) + 4;
            *error = point;
        } */
        icmp->icmp_sum = 0;
        icmp->icmp_sum = cksum(icmp, sizeof(sr_icmp_t3_hdr_t));
        struct sr_arpentry *arp;
        
        if ((arp = sr_arpcache_lookup(&sr->cache, packet->ip_dst)) == NULL) {
            struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, packet->ip_dst, (uint8_t *)temp, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), in_interface->name);
            req->interface = in_interface->name;
            sr_handle_arp_req(sr, req);
            return;
        }
        
        /* modify ethernet header: packet should be send out recieved interface */
        memcpy(temp->ether_dhost, arp->mac, ETHER_ADDR_LEN);
        memcpy(temp->ether_shost, in_interface->addr, ETHER_ADDR_LEN);

        sr_send_packet(sr, (uint8_t *) temp, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), in_interface->name);
        free(arp);
    }
    free(temp);
 
}

/* handles incoming IP packet */
void sr_handle_ip(struct sr_instance *sr, sr_ethernet_hdr_t *ethh, unsigned int len, char* interface)
{
    /* Initial pointer setup */
    sr_ip_hdr_t *iph = (sr_ip_hdr_t *) (ethh + 1);
    uint16_t hip_head, hip_sum, hip_ttl, hip_dst, hicmp_sum, hip_len;
    struct sr_if* in_interface;
    if ((in_interface = sr_get_interface(sr, interface)) == 0) {
        fprintf(stderr, "Unable to find interface.\n");
    }

    /* Find matching interface IP if necessary */
    struct sr_if *temp;
    uint32_t raddr;
    for (temp = sr->if_list; temp != NULL; temp = temp->next) {
        if (temp->ip == iph->ip_dst) {
            raddr = temp->ip;
            break;
        }
        else
            raddr = in_interface->ip;
    }
    
    /* sanity check */
    size_t minlength = sizeof(sr_ip_hdr_t);
    hip_head = 4 * iph->ip_hl;
    if (hip_head < minlength) {
        fprintf(stderr, "NOT a valid IP packet: invalid length.\n");
        return;
    }
    
    hip_sum = iph->ip_sum;
    iph->ip_sum = 0;
    if (hip_sum == cksum(iph, hip_head)) {
        hip_ttl = iph->ip_ttl;
        hip_len = ntohs(iph->ip_len);
        if (hip_ttl > 0) { /* sanity check, real ttl decrementing and checking are done later */
            
            /* copy original packet for future reference */
            sr_ethernet_hdr_t *ethh_cpy;
            if ((ethh_cpy = malloc(sizeof(sr_ethernet_hdr_t) + hip_head + 2 * sizeof(uint32_t))) == NULL) {
                fprintf(stderr, "malloc failed.\n");
                return;
            }
            else
                memcpy(ethh_cpy, ethh, sizeof(sr_ethernet_hdr_t) + hip_head + 2 * sizeof(uint32_t));
            
            /* determine if icmp packet destined to us */
            hip_dst = ntohl(iph->ip_dst);
            if (iph->ip_p == ip_protocol_icmp && temp) {
                sr_icmp_hdr_t *ich = (sr_icmp_hdr_t *) (((uint8_t *) iph) + hip_head);
   
                hicmp_sum = ntohs(ich->icmp_sum);
                ich->icmp_sum = 0;
                if (hicmp_sum == ntohs(cksum(ich, hip_len - hip_head))) {

                    /* packet is echo request */
                    if (ich->icmp_type == 8 && ich->icmp_code == 0) {
   
                        ich->icmp_type = 0;
                        ich->icmp_sum = cksum(ich, hip_len - hip_head);
                        
                        iph->ip_dst = iph->ip_src;
                        iph->ip_src = raddr;
                        
                        /*
                        check packet for options
                            uint8_t *opt;
                        if (iph->ip_hl > 5) {
                            opt = (uint8_t *) (iph + 1);
                            
                            do {
                                if (*opt == Record_Route) {
                                    uint8_t *len, *point, *pointer;
                                    
                                    len = opt + 1;
                                    point = len + 1;
                                    pointer = *point + opt;
                                    opt = opt + *len;
                                    
                                    if (*point > (*len) - sizeof(uint32_t *)) {
                                        if (opt == pointer) {
                                            sr_handle_icmp(sr, ethh_cpy, in_interface, 12, 0, *point, NULL, NULL);
                                            continue;
                                        }
                                        else {
                                            sr_handle_icmp(sr, ethh_cpy, in_interface, 12, 0, *point, NULL, NULL);
                                            free(ethh_cpy);
                                            return;
                                        }
                                    }
                                    else {
                                        *pointer = raddr;
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
                                    
                                    masking to access 4 bit entries
                                    flag = *det & 15;
                                    oflow = (*det & 140) >> 4;
                                    opt = opt + *len;
                                    
                                    if (oflow == 15) {
                                        sr_handle_icmp(sr, ethh_cpy, in_interface, 12, 0, sizeof(uint8_t) * 3, NULL, NULL);
                                        free(ethh_cpy);
                                        return;
                                    }
                                    else {
                                        if (flag == 0) {
                                            if (*point > (*len) - sizeof(uint32_t *)) {
                                                if (opt == pointer) { record only time
                                                    sr_handle_icmp(sr, ethh_cpy, in_interface, 12, 0, *point, NULL, NULL);
                                                    *det += 16;  1<<4
                                                    continue;
                                                }
                                                else {
                                                    sr_handle_icmp(sr, ethh_cpy, in_interface, 12, 0, *point, NULL, NULL);
                                                    free(ethh_cpy);
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
                                        else if (flag == 1) { record both time and address
                                            if (*point > (*len) - 2 * sizeof(uint32_t *)) {
                                                if (opt == pointer) {
                                                    sr_handle_icmp(sr, ethh_cpy, in_interface, 12, 0, *point, NULL, NULL);
                                                    *det += 16;
                                                    continue;
                                                }
                                                else {
                                                    sr_handle_icmp(sr, ethh_cpy, in_interface, 12, 0, *point, NULL, NULL);
                                                    free(ethh_cpy);
                                                    return;
                                                }
                                            }
                                            else {
                                                int time;
                                                struct timeval tv;
                                                
                                                gettimeofday(&tv, NULL);
                                                time = tv.tv_usec *1000;
                                                
                                                *pointer = raddr;
                                                pointer += sizeof(uint32_t *);
                                                *point += sizeof(uint32_t *);
                                                *pointer = htonl(time);
                                                *point += sizeof(uint32_t *);
                                                continue;
                                            }
                                        }
                                        else if (flag == 3) { record time if matching address
                                            if (*point > (*len) - sizeof(uint32_t *)) {
                                                if (opt == pointer) {
                                                    sr_handle_icmp(sr, ethh_cpy, in_interface, 12, 0, *point, NULL, NULL);
                                                    continue;
                                                }
                                                else {
                                                    sr_handle_icmp(sr, ethh_cpy, in_interface, 12, 0, *point, NULL, NULL);
                                                    free(ethh_cpy);
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
                                            sr_handle_icmp(sr, ethh_cpy, in_interface, 12, 0, *point, NULL, NULL);
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
                                
                                opt++;
                            } while ((sr_icmp_hdr_t *) opt < ich);
                        }
                        */
                        
                        /*modify packet for sending*/
                        iph->ip_ttl = 64;
                        iph->ip_sum = 0;
                        iph->ip_sum = cksum(iph, hip_head);
                        
                        struct sr_arpentry *arp;
                        if ((arp = sr_arpcache_lookup(&sr->cache, iph->ip_dst)) == NULL) {
                            struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, iph->ip_dst, (uint8_t *) ethh, len, interface);
                            req->interface = interface;
                            sr_handle_arp_req(sr, req);
                            return;
                        }
                        
                        /* modify ethernet header: packet should be send out recieved interface */
                        memcpy(ethh->ether_dhost, arp->mac, ETHER_ADDR_LEN);
                        memcpy(ethh->ether_shost, in_interface->addr, ETHER_ADDR_LEN);

                        /*send packet out on recieved interface */
                        sr_send_packet(sr, (uint8_t *) ethh, len, interface);
                        free(arp);
                        free(ethh_cpy);
                    }
                    else if (ich->icmp_type == 30) {
                        /* traceroute icmp message */
                        fprintf(stderr, "Received ICMP traceroute message.\n");
                        free(ethh_cpy);
                    }
                    else{
                        fprintf(stderr, "Dunno how to process this icmp type.\n");
                        free(ethh_cpy);
                    }
                }
                else {
                    fprintf(stderr, "Invalid ICMP checksum.\n");
                    free(ethh_cpy);
                }
            }
            else if ((iph->ip_p == ip_protocol_udp || iph->ip_p == ip_protocol_tcp)  && temp) {
                sr_arpcache_insert(&sr->cache, ethh_cpy->ether_shost, iph->ip_src);
                sr_handle_icmp(sr, ethh_cpy, in_interface, 3, 3, 0, NULL, NULL);
                free(ethh_cpy);
            }
            else if (temp) {
                fprintf(stderr, "Dropping ip packets destined to us. Not TCP/UDP.\n");
                free(ethh_cpy);
            }
            else { /* forward packet normally */
                struct sr_rt *entry, *match = NULL;
                struct sr_arpentry *arp;
                struct sr_if* out_interface;
                /*sr_ip_tr_hdr_t *tr;
                int has_traceroute = 0, to_origin = 0 j, n;*/
                
                sr_arpcache_insert(&sr->cache, ethh_cpy->ether_shost, iph->ip_src);
                iph->ip_ttl--;
                if (iph->ip_ttl == 0) {
                    sr_handle_icmp(sr, ethh_cpy, in_interface, 11, 0, 0, NULL, NULL);
                    free(ethh_cpy);
                    return;
                }
                
                /* check for traceroute option 
                uint8_t *opt;
                if (iph->ip_hl > 5) {
                    opt = (uint8_t *) (iph + 1);
                    
                    do {
                        if (*opt == Traceroute) {
                            tr = (sr_ip_tr_hdr_t *) opt;
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
                        n++;
                    } while (n + sizeof(sr_ip_hdr_t) < hip_head);
                }
                */
                iph->ip_sum = 0;
                iph->ip_sum = cksum(iph, hip_head);
                
                /* find routing entry with longest match ip with ip_dst */
                uint16_t max = 0;
                uint32_t masked = 0;
                for (entry = sr->routing_table; entry != NULL; entry = entry->next) {
                    uint32_t rt_dst = entry->dest.s_addr & entry->mask.s_addr;
                    uint32_t dst = iph->ip_dst & entry->mask.s_addr;
                    
                    if (dst == rt_dst) {
                        masked = ntohl((entry->mask).s_addr);
                        if (masked > max) {
                            max = masked;
                            match = entry;
                        }
                    }
                }

                /* no interface to forward */
                if (match == NULL) {
                    /*if (has_traceroute ) {
                        packet must be on outbound trip to need a traceroute icmp msg
                        if (!to_origin)
                            sr_handle_icmp(sr, ethh_cpy, in_interface, 30, 1, 0, NULL, tr);
                    }
                    else*/
                    sr_handle_icmp(sr, ethh_cpy, in_interface, 3, 0, 0, NULL, NULL);
                    
                    free(ethh_cpy);
                }
                else {
                    /* find matching interface with routing entry */
                    if ((out_interface = sr_get_interface(sr, match->interface)) == 0) {
                        fprintf(stderr, "Unable to find interface.\n");
                    }
                    
                    /* find dest MAC addr in arp cache */
                    if ((arp = sr_arpcache_lookup(&sr->cache, iph->ip_dst)) == NULL) {/* handle arp requesting */
                        struct sr_arpreq* req;
                        req = sr_arpcache_queuereq(&sr->cache, iph->ip_dst, (uint8_t *) ethh, len, match->interface);
                        req->interface = match->interface;
                        sr_handle_arp_req(sr, req);
                        free(ethh_cpy);
                        return;
                    }
                    else {
                        memcpy(ethh->ether_dhost, arp->mac, ETHER_ADDR_LEN);
                        memcpy(ethh->ether_shost, out_interface->addr, ETHER_ADDR_LEN);
                        free(arp);
                    }

                    /* send icmp traceroute if needed
                    if (has_traceroute)
                        sr_handle_icmp(sr, ethh_cpy, in_interface, 30, 0, 0, out_interface, tr);
                    */
                    /* send packet */

                    sr_send_packet(sr, (uint8_t *) ethh, len, match->interface);
                    free(ethh_cpy);
                }
            }
        }
        else {
            fprintf(stderr, "insane packet: TTL = 0\n");
        }
    }
    else
        fprintf(stderr, "Invalid checksum.\n");
    return;
}


void sr_handle_arp(struct sr_instance *sr, sr_ethernet_hdr_t *ethh, unsigned int len, char* interface)
{
    /* initial setup */
    sr_arp_hdr_t *arh = (sr_arp_hdr_t *) (ethh +1);
    struct sr_if* in_interface;
    if ((in_interface = sr_get_interface(sr, interface)) == 0) {
        fprintf(stderr, "Unable to find interface.\n");
    }
    
    /* Compare ARP requested IP with router interfaces */
    struct sr_if *temp;
    uint32_t raddr;
    for (temp = sr->if_list; temp != NULL; temp = temp->next) {
        if (temp->ip == arh->ar_tip) {
            raddr = temp->ip;
            break;
        }
        else
            raddr = in_interface->ip;
    }
    
    if (arh->ar_op == htons(arp_op_request)) {
        if (temp) {
            /*matching ip, so add to arp cache */
            struct sr_arpentry *arp, *temp_arp;
            int j;
            
            if ((arp = sr_arpcache_lookup(&sr->cache, arh->ar_sip) == 0)) { /* insert to arp cache */
                sr_arpcache_insert(&sr->cache, arh->ar_tha, arh->ar_sip);
            }
            else { /* or refresh entry if already exist */
                for (j = 0; sr->cache.entries[j].valid == 0 || j == SR_ARPCACHE_SZ; j++) {
                    temp_arp = &sr->cache.entries[j];
                    if (arp->ip == temp_arp->ip) {
                        temp_arp->added = time(NULL);
                        break;
                    }
                }
                free(arp);
            }
            
            /* fill out ARP reply */
            arh->ar_op = htons(arp_op_reply);
            arh->ar_tip = arh->ar_sip;
            arh->ar_sip = temp->ip;
            
            memcpy(arh->ar_tha, arh->ar_sha, ETHER_ADDR_LEN);
            memcpy(arh->ar_sha, temp->addr, ETHER_ADDR_LEN);
            memcpy(ethh->ether_dhost, arh->ar_tha, ETHER_ADDR_LEN);
            memcpy(ethh->ether_shost, arh->ar_sha, ETHER_ADDR_LEN);

            sr_send_packet(sr, (uint8_t *) ethh, len, interface);
        }
    }
    
    else if (arh->ar_op == htons(arp_op_reply)) {
        struct sr_arpreq *entry;
        /* ARP reply iff we sent an ARP request, so we should add ARP reply to cache */
        entry = sr_arpcache_insert(&sr->cache, arh->ar_sha, arh->ar_sip);
        
        if (entry == NULL) {
            fprintf(stderr, "no arprequest in queue.\n");
        }
        else {
            struct sr_packet *packet;
            
            /* send all waiting packets out */
            for (packet = entry->packets; packet != NULL; packet = packet->next) { /* need to send icmp for traceroute */
                sr_ethernet_hdr_t *temp = (sr_ethernet_hdr_t *) packet->buf;
                sr_ip_hdr_t *iph;
                /*sr_ip_tr_hdr_t *tr;
                int has_traceroute = 0;*/
                 struct sr_if *out_interface;
                if ((out_interface = sr_get_interface(sr, packet->iface)) == NULL)
                    fprintf(stderr, "cannot find interface\n");
                
                iph = (sr_ip_hdr_t *) (temp +1);
                /*
                uint8_t *opt;
                if (iph->ip_hl > 5) {
                    opt = (uint8_t *) (iph + 1);
                    
                    int n;
                    do {
                        if (*opt == Traceroute) {
                            tr = (sr_ip_tr_hdr_t *) opt;
                            has_traceroute = 1;
                            break;
                        }
                        
                        opt++;
                        n++;
                    } while (n + sizeof(sr_ip_hdr_t) < iph->ip_hl * 4);
                }
                */
                memcpy(temp->ether_dhost, arh->ar_sha, ETHER_ADDR_LEN);
                memcpy(temp->ether_shost, out_interface->addr, ETHER_ADDR_LEN);

                /*
                if (has_traceroute)
                    sr_handle_icmp(sr, temp, in_interface, 30, 0, 0, out_interface, tr);*/
                sr_send_packet(sr, packet->buf, packet->len, packet->iface);
            }
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
    
    sr_ethernet_hdr_t *ethh;
    ethh = (sr_ethernet_hdr_t *) packet;
    uint16_t ether_type = ntohs(ethh->ether_type);
    if (ether_type == ethertype_ip) {
        sr_handle_ip(sr, ethh, len, interface);
    }
    else if (ether_type == ethertype_arp){
        sr_handle_arp(sr, ethh, len, interface);
    }
}/* end sr_ForwardPacket */

