













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
                    sr_handle_icmp(sr, ethh_cpy, in_interface, 12, 0, raddr, *point, NULL, NULL);
                    continue;
                }
                else {
                    sr_handle_icmp(sr, ethh_cpy, in_interface, 12, 0, raddr, *point, NULL, NULL);
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
                sr_handle_icmp(sr, ethh_cpy, in_interface, 12, 0, raddr, sizeof(uint8_t) * 3, NULL, NULL);
                free(ethh_cpy);
                return;
            }
            else {
                if (flag == 0) {
                    if (*point > (*len) - sizeof(uint32_t *)) {
                        if (opt == pointer) { record only time
                            sr_handle_icmp(sr, ethh_cpy, in_interface, 12, 0, raddr, *point, NULL, NULL);
                            *det += 16;  1<<4
                            continue;
                        }
                        else {
                            sr_handle_icmp(sr, ethh_cpy, in_interface, 12, 0, raddr, *point, NULL, NULL);
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
                            sr_handle_icmp(sr, ethh_cpy, in_interface, 12, 0, raddr, *point, NULL, NULL);
                            *det += 16;
                            continue;
                        }
                        else {
                            sr_handle_icmp(sr, ethh_cpy, in_interface, 12, 0, raddr, *point, NULL, NULL);
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
                            sr_handle_icmp(sr, ethh_cpy, in_interface, 12, 0, raddr, *point, NULL, NULL);
                            continue;
                        }
                        else {
                            sr_handle_icmp(sr, ethh_cpy, in_interface, 12, 0, raddr, *point, NULL, NULL);
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
                    sr_handle_icmp(sr, ethh_cpy, in_interface, 12, 0, raddr, *point, NULL, NULL);
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

