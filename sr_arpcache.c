#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_rt.h"

#define TRACEROUTE 82

void sr_send_icmp(struct sr_instance* sr, struct sr_packet *packet, uint8_t type, uint8_t code)
{
    sr_ethernet_hdr_t *temp, *ethh;
    sr_ip_hdr_t *icmp_packet, *iph;
    struct sr_if *interface;
    struct sr_rt *entry, *match;
    sr_icmp_t3_hdr_t *ich;
    
    if ((temp = calloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), 1)) == NULL)
        fprintf(stderr, "calloc failed,\n");
    
    temp->ether_type = htons(ethertype_ip);
    
    icmp_packet = (sr_ip_hdr_t *) (temp + 1);
    ethh = (sr_ethernet_hdr_t *) packet->buf;
    iph = (sr_ip_hdr_t *) (ethh + 1);
    ich = (sr_icmp_t3_hdr_t *) (icmp_packet + 1);

    icmp_packet->ip_hl = 5;
    icmp_packet->ip_v = 4;
    icmp_packet->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    icmp_packet->ip_ttl = 64;
    icmp_packet->ip_off = htons(IP_DF);
    icmp_packet->ip_p = ip_protocol_icmp;
    icmp_packet->ip_dst = iph->ip_src;

    uint16_t max = 0;
    uint32_t masked = 0;
    for (entry = sr->routing_table; entry != NULL; entry = entry->next) {
        uint32_t rt_dst = entry->dest.s_addr & entry->mask.s_addr;
        uint32_t dst = icmp_packet->ip_dst & entry->mask.s_addr;
        
        if (dst == rt_dst) {
            masked = ntohl((entry->mask).s_addr);
            if (masked > max) {
                max = masked;
                match = entry;
            }
        }
    }
    
    if ((interface = sr_get_interface(sr, match->interface)) == NULL) {
        fprintf(stderr, "cannot find interface.\n");
    }
    
    icmp_packet->ip_src = interface->ip;
    icmp_packet->ip_sum = cksum(icmp_packet, sizeof(sr_ip_hdr_t));
    
    ich->icmp_type = type;
    ich->icmp_code = code;
    
    memcpy(ich->data, iph, sizeof(sr_ip_hdr_t) + 2 * sizeof(uint32_t));
    ich->icmp_sum = cksum(ich, sizeof(sr_icmp_t3_hdr_t));
    
    struct sr_arpentry *arp;
    if ((arp = sr_arpcache_lookup(&sr->cache, icmp_packet->ip_dst)) == NULL) {
        struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, icmp_packet->ip_dst, (uint8_t *)temp, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface->name);
        req->interface = interface->name;
        sr_handle_arp_req(sr, req);
        return;
    }
    
    /* modify ethernet header: packet should be send out recieved interface */
    memcpy(ethh->ether_dhost, arp->mac, ETHER_ADDR_LEN);
    memcpy(ethh->ether_shost, interface->addr, ETHER_ADDR_LEN);
    
    sr_send_packet(sr, (uint8_t *) temp, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), match->interface);
    free(temp);
    free(arp);
}


void sr_send_arp(struct sr_instance* sr, struct sr_arpreq *req)
{
    sr_ethernet_hdr_t *temp;
    sr_arp_hdr_t *arp;
    struct sr_if *interface;
    int i;
    
    if ((interface = sr_get_interface(sr, req->interface)) == NULL)
        fprintf(stderr, "no interface found.\n");
    
    temp = (sr_ethernet_hdr_t *) calloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), 1);
    arp = (sr_arp_hdr_t *) (temp + 1);
    
    temp->ether_type = htons(ethertype_arp);
    
    memcpy(temp->ether_shost, interface->addr, ETHER_ADDR_LEN);
    memcpy(arp->ar_sha, interface->addr, ETHER_ADDR_LEN);
    for (i = 0; i < ETHER_ADDR_LEN; i++) {
        temp->ether_dhost[i] = 0xFF;
    }

    arp->ar_hrd = htons(arp_hrd_ethernet);
    arp->ar_pro = htons(ethertype_ip);
    arp->ar_hln = ETHER_ADDR_LEN;
    arp->ar_pln = 4;
    arp->ar_op = htons(arp_op_request);
    arp->ar_sip = interface->ip;
    arp->ar_tip = req->ip;
    
    sr_send_packet(sr, (uint8_t *) temp, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface->name);
    free(temp);
    
    req->sent = time(NULL);
    req->times_sent++;
}

void sr_handle_arp_req(struct sr_instance *sr, struct sr_arpreq *req) {
    time_t curtime = time(NULL);
    if (difftime(curtime, req->sent) > 1.0 ) {
        
        if (req->times_sent >= 5) {
            struct sr_packet *packet;
            for (packet = req->packets; packet != NULL; packet = packet->next) {
                sr_send_icmp(sr, packet, 3, 1);
            }
            sr_arpreq_destroy(&sr->cache, req);
        }
        else {
            sr_send_arp(sr, req);
        }
    }
    
}
/* arp not successful handle appropriately. handle normal ICMP or check condition to handle ICMP for traceroute */

/*
 This function gets called every second. For each request sent out, we keep
 checking whether we should resend an request or destroy the arp request.
 See the comments in the header file for an idea of what it should look like.
 */
void sr_arpcache_sweepreqs(struct sr_instance *sr) {
    struct sr_arpreq *entry, *temp;
    for (entry = sr->cache.requests; entry != NULL; entry = temp) {
        temp = entry->next;
        sr_handle_arp_req(sr, entry);
    }
    
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
 You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
	pthread_mutex_lock(&(cache->lock));
    
	struct sr_arpentry *entry = NULL, *copy = NULL;
    
	int i;
	for (i = 0; i < SR_ARPCACHE_SZ; i++) {
		if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
			entry = &(cache->entries[i]);
		}
	}
    
	/* Must return a copy b/c another thread could jump in and modify
     table after we return. */
	if (entry) {
		copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
		memcpy(copy, entry, sizeof(struct sr_arpentry));
	}
    
	pthread_mutex_unlock(&(cache->lock));
    
	return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
 the queue, adds the packet to the linked list of packets for this sr_arpreq
 that corresponds to this ARP request. You should free the passed *packet.
 
 A pointer to the ARP request is returned; it should not be freed. The caller
 can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
	pthread_mutex_lock(&(cache->lock));
    
	struct sr_arpreq *req;
	for (req = cache->requests; req != NULL; req = req->next) {
		if (req->ip == ip) {
			break;
		}
	}
    
	/* If the IP wasn't found, add it */
	if (!req) {
		req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
		req->ip = ip;
		req->next = cache->requests;
		cache->requests = req;
	}
    
	/* Add the packet to the list of packets for this request */
	if (packet && packet_len && iface) {
		struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
		new_pkt->buf = (uint8_t *)malloc(packet_len);
		memcpy(new_pkt->buf, packet, packet_len);
		new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
		strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
		new_pkt->next = req->packets;
		req->packets = new_pkt;
	}
    
	pthread_mutex_unlock(&(cache->lock));
    
	return req;
}

/* This method performs two functions:
 1) Looks up this IP in the request queue. If it is found, returns a pointer
 to the sr_arpreq with this IP. Otherwise, returns NULL.
 2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
	pthread_mutex_lock(&(cache->lock));
    
	struct sr_arpreq *req, *prev = NULL, *next = NULL;
	for (req = cache->requests; req != NULL; req = req->next) {
		if (req->ip == ip) {
			if (prev) {
				next = req->next;
				prev->next = next;
			}
			else {
				next = req->next;
				cache->requests = next;
			}
            
			break;
		}
		prev = req;
	}
    
	int i;
	for (i = 0; i < SR_ARPCACHE_SZ; i++) {
		if (!(cache->entries[i].valid))
			break;
	}
    
	if (i != SR_ARPCACHE_SZ) {
		memcpy(cache->entries[i].mac, mac, 6);
		cache->entries[i].ip = ip;
		cache->entries[i].added = time(NULL);
		cache->entries[i].valid = 1;
	}
    
	pthread_mutex_unlock(&(cache->lock));
    
	return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
 entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
	pthread_mutex_lock(&(cache->lock));
    
	if (entry) {
		struct sr_arpreq *req, *prev = NULL, *next = NULL;
		for (req = cache->requests; req != NULL; req = req->next) {
			if (req == entry) {
				if (prev) {
					next = req->next;
					prev->next = next;
				}
				else {
					next = req->next;
					cache->requests = next;
				}
                
				break;
			}
			prev = req;
		}
        
		struct sr_packet *pkt, *nxt;
        
		for (pkt = entry->packets; pkt; pkt = nxt) {
			nxt = pkt->next;
			if (pkt->buf)
				free(pkt->buf);
			if (pkt->iface)
				free(pkt->iface);
			free(pkt);
		}
        
		free(entry);
	}
    
	pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
	fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
	fprintf(stderr, "-----------------------------------------------------------\n");
    
	int i;
	for (i = 0; i < SR_ARPCACHE_SZ; i++) {
		struct sr_arpentry *cur = &(cache->entries[i]);
		unsigned char *mac = cur->mac;
		fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
	}
    
	fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {
	/* Seed RNG to kick out a random entry if all entries full. */
	srand(time(NULL));
    
	/* Invalidate all entries */
	memset(cache->entries, 0, sizeof(cache->entries));
	cache->requests = NULL;
    
	/* Acquire mutex lock */
	pthread_mutexattr_init(&(cache->attr));
	pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
	int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
	return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
	return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
 more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
	struct sr_instance *sr = sr_ptr;
	struct sr_arpcache *cache = &(sr->cache);
    
	while (1) {
		sleep(1.0);
        
		pthread_mutex_lock(&(cache->lock));
        
		time_t curtime = time(NULL);
        
		int i;
		for (i = 0; i < SR_ARPCACHE_SZ; i++) {
			if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
				cache->entries[i].valid = 0;
			}
		}
        
		sr_arpcache_sweepreqs(sr);
        
		pthread_mutex_unlock(&(cache->lock));
	}
    
	return NULL;
}

