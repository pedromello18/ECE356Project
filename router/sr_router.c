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
#include <string.h>
#include <stdlib.h>


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

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  /* Sanity check the packet (meets minimum length and has correct checksum). */
  if(len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) /*minimum length of packet we can receive, 34 bytes*/
  {
    printf("Invalid length > packet dropped. \n");
    return;
  }

  uint8_t *packet_to_send = (uint8_t *)malloc(len);
  memcpy(packet_to_send, packet, len);

  sr_ethernet_hdr_t *p_ethernet_header = (sr_ethernet_hdr_t *)packet_to_send;
  uint16_t packet_type_id = p_ethernet_header->ether_type;
  if(packet_type_id == htons(ethertype_arp)) /* ARP */
  {
    printf("Received ARP packet. \n");
    sr_arp_hdr_t *p_arp_header = (sr_arp_hdr_t *)(packet_to_send + sizeof(sr_ethernet_hdr_t));
    unsigned short arp_opcode = p_arp_header->ar_op;
    uint32_t ip_dest = p_arp_header->ar_tip;

    if (arp_opcode == htons(arp_op_request))
    {
      printf("ARP Request.\n");
      struct sr_if *cur = sr->if_list;
      while(cur)
      {
        if(cur->ip == ip_dest)
        {
          p_arp_header->ar_op = htons(arp_op_reply);
          memcpy(p_arp_header->ar_sha, cur->addr, ETHER_ADDR_LEN);
          p_arp_header->ar_sip = cur->ip;
          memcpy(p_arp_header->ar_tha, p_arp_header->ar_sha, ETHER_ADDR_LEN);
          p_arp_header->ar_tip = p_arp_header->ar_sip;
          memcpy(p_ethernet_header->ether_dhost, p_ethernet_header->ether_shost, ETHER_ADDR_LEN);
          memcpy(p_ethernet_header->ether_shost, cur->addr, ETHER_ADDR_LEN);

          sr_send_packet(sr, packet_to_send, len, interface);
          return;
        }
        cur = cur->next;
      }
      return;
    }
    else if (arp_opcode == htons(arp_op_reply)) 
    {
      printf("ARP Reply.\n");
      struct sr_if *cur = sr->if_list;
      while(cur)
      {
        if(p_arp_header->ar_tip == cur->ip)
        {
          printf("Inserting entry into our arpcache.\n");
          struct sr_arpreq *arpreq = sr_arpcache_insert(&sr->cache, p_arp_header->ar_sha, p_arp_header->ar_sip);   
          if(arpreq)
          {
            struct sr_packet *queued_packet = arpreq->packets;
            while (queued_packet)
            {
              sr_ethernet_hdr_t *p_out_ethernet_header = (sr_ethernet_hdr_t *) queued_packet->buf;
              memcpy(p_out_ethernet_header->ether_dhost, p_arp_header->ar_sha, ETHER_ADDR_LEN);
              memcpy(p_out_ethernet_header->ether_shost, p_arp_header->ar_tha, ETHER_ADDR_LEN);
              sr_send_packet(sr, queued_packet->buf, queued_packet->len, queued_packet->iface);
              queued_packet = queued_packet->next;
            }
            sr_arpreq_destroy(&sr->cache, arpreq);
          }   
          break;
        }
        cur = cur->next;
      }
      return;
    }
  } 
  else if(packet_type_id == htons(ethertype_ip)) /* IP */
  {
    sr_ip_hdr_t *p_ip_header = (sr_ip_hdr_t *)(packet_to_send + sizeof(sr_ethernet_hdr_t));
    printf("Received IP packet. \n");
    
    uint16_t received_checksum = p_ip_header->ip_sum;
    p_ip_header->ip_sum = 0;
    uint16_t expected_checksum = cksum(p_ip_header, p_ip_header->ip_hl * 4); /*Convert words to bytes*/
    p_ip_header->ip_sum = received_checksum;
    
    if(received_checksum != expected_checksum)
    {
      printf("Checksum detected an error > packet dropped. \n");
      printf("Expected: 0x%x\nReceived: 0x%x", expected_checksum, received_checksum);
      return;
    }

    /* Decrement the TTL by 1, and recompute the packet checksum over the modified header. */
    p_ip_header->ip_ttl--;
    if (p_ip_header->ip_ttl == 0)
    {
      printf("Time exceeded. \n");
      send_icmp_t3_packet(sr, packet_to_send, ICMP_TYPE_TIME_EXCEEDED, ICMP_CODE_TIME_EXCEEDED, interface); /*Per ed post? Don't know*/
      return;
    }
    /*p_ip_header->ip_sum = cksum(p_ip_header, p_ip_header->ip_len); Dont think its necessary*/ 

    /* Check if packet is for router */
    struct sr_if *cur = sr->if_list;
      while(cur)
      {
        if(p_ip_header->ip_dst == cur->ip)
        {
          printf("Packet for router. \n");
          if(p_ip_header->ip_p == ip_protocol_icmp)
          {
            printf("ICMP Message - ");
            sr_icmp_hdr_t *p_icmp_header = (sr_icmp_hdr_t *)((uint8_t *) p_ip_header + sizeof(sr_ip_hdr_t));
            printf("Type: %d, ", p_icmp_header->icmp_type);
            printf("Code: %d\n", p_icmp_header->icmp_code);
            if((p_icmp_header->icmp_type == ICMP_TYPE_ECHO_REQUEST) && (p_icmp_header->icmp_code == ICMP_CODE_ECHO_REQUEST))
            {
              printf("Sending echo reply.\n");
              send_icmp_packet(sr, packet_to_send, len, ICMP_TYPE_ECHO_REPLY, ICMP_CODE_ECHO_REPLY, interface); /* echo reply */
            }
            else
            {
              printf("Not echo reply > sending port unreachable.\n");
              send_icmp_t3_packet(sr, packet_to_send, ICMP_TYPE_UNREACHABLE, ICMP_CODE_PORT_UNREACHABLE, interface); /* port unreachable */
            }
          }
          else
          {
            printf("Protocol is not ICMP > sending port unreachable. \n");
            send_icmp_t3_packet(sr, packet_to_send, ICMP_TYPE_UNREACHABLE, ICMP_CODE_PORT_UNREACHABLE, interface); /* port unreachable */
          }
          return;
        }
        cur = cur->next;
      }
      printf("Packet isn't for me. I will forward her!\n");
      char *iface_out_name = best_prefix(sr, p_ip_header->ip_dst);
      if (iface_out_name == NULL)
      {
        send_icmp_t3_packet(sr, packet_to_send, ICMP_TYPE_UNREACHABLE, ICMP_CODE_DESTINATION_NET_UNREACHABLE, interface);
        return;
      }
      struct sr_if *cur_if = sr->if_list;
      struct sr_if *iface_out;
      while(cur_if)
      {
        if (strcmp(iface_out_name, cur_if->name) == 0) 
        {
          iface_out = cur_if;
          break;
        }
        cur_if = cur_if->next;
      }
    struct sr_arpentry *arpentry = sr_arpcache_lookup(&sr->cache, iface_out->ip);
    if (arpentry)
    {
      printf("ok so she was in our arpcache. Should find her in interface list...\n");
      struct sr_if *cur = sr->if_list;
      while(cur)
      {
        if(memcmp(arpentry->mac, cur->addr, ETHER_ADDR_LEN) == 0)
        {
          printf("Found address from arpentry in interface list.\n");
          uint8_t temp_ether_dhost[ETHER_ADDR_LEN];
          memcpy(temp_ether_dhost, p_ethernet_header->ether_dhost, ETHER_ADDR_LEN);
          memcpy(p_ethernet_header->ether_dhost, p_ethernet_header->ether_shost, ETHER_ADDR_LEN);
          memcpy(p_ethernet_header->ether_shost, temp_ether_dhost, ETHER_ADDR_LEN);
          sr_send_packet(sr, packet_to_send, len, cur->name);
          break;
        }
      }
      printf("Freeing arpentry now.\n");
      free(arpentry);
    }
    else
    {
      printf("this diva was not cached :(\n");
      struct sr_arpreq *arpreq = sr_arpcache_queuereq(&sr->cache, p_ip_header->ip_dst, packet, len, iface_out_name);
      handle_arpreq(sr, arpreq);
    }
  }
  else
  {
    printf("Invalid packet type > packet dropped.\n");
    printf("Packet type: 0x%x\n", packet_type_id);
    return;
  } 
} /* end sr_handlePacket */

char *best_prefix(struct sr_instance *sr, uint32_t ip_addr) {
  struct sr_rt *cur_rt = sr->routing_table;
  char *best_match = NULL;  
  uint32_t best_match_mask = 0;

  while (cur_rt) {
    uint32_t cur_mask = cur_rt->mask.s_addr;
    uint32_t cur_addr = cur_rt->dest.s_addr;

    if ((cur_addr & cur_mask) == (ip_addr & cur_mask)) {
      if (cur_mask > best_match_mask) {
        best_match = cur_rt->interface; 
        best_match_mask = cur_mask;
      }
    }
    cur_rt = cur_rt->next;
  }
  
  printf("Best match: %s\n", best_match);
  return best_match;
}
