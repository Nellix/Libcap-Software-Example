//
//  main.c
//  Risso_LIBCAP
//
//  Created by Università on 09/12/16.
//  Copyright © 2016 Università. All rights reserved.
//

#include <stdio.h>
#include <pcap.h>


#define LINE_LEN 16


void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data);



struct ether_header //6+6+2 = 14
{
    u_int8_t ether_dhost[6];
    u_int8_t ether_shost[6];
    u_int16_t ether_type;
};

struct ip_header //20
{
    u_int8_t lenver;
    u_int8_t ip_tos;
    u_int16_t ip_len;
    u_int16_t ip_id;
    u_int16_t ip_off;
    u_int8_t ip_ttl;
    u_int8_t p;
    u_int16_t ip_sum;
    u_int8_t ip_src[4];
    u_int8_t ip_dst[4];
};

struct tcp_header //2+2+4+4+1 = 13
{
    u_int16_t port_src;
    u_int16_t port_dest;
    u_int32_t   sequence;
    u_int32_t   ack;
    u_int8_t len;
};

struct udp_header
{
    u_int16_t port_src;
    u_int16_t port_dest;
};


int main(int argc, char *argv[])
{
    pcap_t *fp;
    
    char errbuf[PCAP_ERRBUF_SIZE]; struct pcap_pkthdr *header; const u_char *pkt_data;
    
    
    char *dev;
    
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    printf("Device: %s\n", dev);
    
    fp = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    
    if (fp == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    
        pcap_loop(fp, 0, dispatcher_handler, NULL);

        pcap_close(fp);
        return 0;
    
    
    /*
     -DLT_RAW   Raw IP; the packet begins with an IPv4 or IPv6 header, with the "version" field of the      header indicating whether it's an IPv4 or IPv6 header.
     
     -DLT_EN10MB    IEEE 802.3 Ethernet (10Mb, 100Mb, 1000Mb, and up); the 10MB in the DLT_ name is                             historical.
     
     
     */
    
    
    
    
    
    return(0);
}



void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct ether_header *eptr;
    u_int16_t ethertype;
    struct ip_header *iptr;
    struct tcp_header* tptr;
    struct udp_header* uptr;

    
    //Cast for Data
    eptr = (struct ether_header *) pkt_data;
   
    printf("TimeStamp :\t%ld:%ld \nLenght :\t(%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);
    
    /* Print on screen the MAC addresses of each packet */
    printf("MAC Src :\t%02x:%02x:%02x:%02x:%02x:%02x \nMAC Dest :\t%02x:%02x:%02x:%02x:%02x:%02x\n",
           eptr->ether_shost[0], eptr->ether_shost[1], eptr->ether_shost[2], eptr->ether_shost[3], eptr->ether_shost[4], eptr->ether_shost[5], eptr->ether_dhost[0], eptr->ether_dhost[1], eptr->ether_dhost[2], eptr->ether_dhost[3], eptr->ether_dhost[4], eptr->ether_dhost[5]);

    
        ethertype= ntohs(eptr->ether_type); /* Converting ethertype from network to host byte order */
    
    
    
    if(ethertype == 0x800)
    {
        printf("Protocollo Rete :\t0x%04x   IP\n", ethertype);
        iptr = (struct ip_header *) &pkt_data[14];

        
        
        printf("IP Src : \t%d.%d.%d.%d \nIP Dst : \t%d.%d.%d.%d \nLength Ip : \t%d\n",iptr->ip_src[0], iptr->ip_src[1], iptr->ip_src[2],iptr->ip_src[3], iptr->ip_dst[0], iptr->ip_dst[1], iptr->ip_dst[2], iptr->ip_dst[3], ntohs(iptr->ip_len));
      
        
        if(iptr->p == 6)
        {
            printf("Protocol Trasporto : \tTCP\n" );
        
            tptr = (struct tcp_header *) &pkt_data[34];
            
            
            printf("Porta Src : \t%d \nPorta Dst : \t%d \n", ntohs(tptr->port_src),ntohs(tptr->port_dest));
            
            
            if(ntohs(tptr->port_dest) == 80)
            {
                printf("Protocollo Applicativo : \t HTTP \n");
                
                if ((header->caplen > (ethertype + ntohs(iptr->ip_len) + ntohs(tptr->len) )))
                    {
                        printf("ciao");
                    }else
                    {
                         printf("Header caplen :\t %d \tPayload : 0x%04x + %d + %d\t\n",header->caplen,ethertype,ntohs(iptr->ip_len),tptr->len);
                        
                        int i = ntohs(iptr->ip_len)-20-20;
                        int j=0;
                        printf("Ip Lenght : %i\n",i);
                        while(i>0)
                        {
                            printf("%c",pkt_data[j+54]);
                            i--;
                            j++;
                        }
                        
                        printf("\n\n****\n\n");

                    }

            }
            else if(ntohs(tptr->port_dest) == 443)
            {
                printf("Protocollo Applicativo : \t HTTPS \n");
                
                if ((header->caplen > (ethertype + ntohs(iptr->ip_len) + ntohs(tptr->len) )))
                {
                    printf("ciao");
                }else
                {
                    printf("Header caplen :\t %d \tPayload : 0x%04x + %d + %d\t\n",header->caplen,ethertype,ntohs(iptr->ip_len),tptr->len);
                    
                    int i = ntohs(iptr->ip_len)-20-20;
                    int j=0;
                    printf("Ip Lenght : %i\n",i);
                    while(i>0)
                    {
                        printf("%c",pkt_data[j+54]);
                        i--;
                        j++;
                    }
                    
                    printf("\n\n****\n\n");
                    
                }
                
            }else
            {
                     printf("Protocollo Applicativo : \t ALTRO \n\n");
            }
            
        
        }else if (iptr->p == 17)
        {
            printf("Protocol Trasporto : \tUDP\n" );
            
            uptr = (struct udp_header *) &pkt_data[34];
            
            
            printf("Porta Src : \t%d \nPorta Dst : \t%d \n\n", ntohs(uptr->port_src),ntohs(uptr->port_dest));
            


        }else
        {
            printf("Protocol Trasporto : \tSCONOSCIUTO\n\n" );

        }
        
    }else
        {
            printf("Protocollo Rete : \tNon IP\n\n");
        }
}








