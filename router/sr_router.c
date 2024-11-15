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

  printf("*** -> Received packet of length %d \n",len);
  int i;
  for(i=0; i<len; i++)
  {
    printf("%x ", *(packet+i));
  }
  printf("\n");

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
      struct sr_if *cur = sr->if_list;
      while(cur)
      {
        if(p_arp_header->ar_tip == cur->ip)
        {
          sr_arpcache_insert(&sr->cache, p_arp_header->ar_sha, p_arp_header->ar_sip);      
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
    
    uint16_t expected_checksum = cksum(p_ip_header, len - sizeof(sr_ethernet_hdr_t));
    uint16_t received_checksum = p_ip_header->ip_sum;
    if(received_checksum != htons(expected_checksum))
    {
      printf("Checksum detected an error > packet dropped. \n");
      printf("Expected: 0x%x\nReceived: 0x%x", expected_checksum, received_checksum);
      return;
    }

    /* Decrement the TTL by 1, and recompute the packet checksum over the modified header. */
    uint8_t received_ttl = p_ip_header->ip_ttl;
    if (received_ttl == 0)
    {
      send_icmp_packet(sr, packet_to_send, len, ICMP_TYPE_TIME_EXCEEDED, ICMP_CODE_TIME_EXCEEDED, interface); 
    }
    p_ip_header->ip_ttl = received_ttl - 1;
    p_ip_header->ip_sum = cksum(p_ip_header, p_ip_header->ip_len); 

    /*Check if packet is for router*/
    struct sr_if *cur = sr->if_list;
      while(cur)
      {
        if(p_ip_header->ip_dst == cur->ip)
        {
          if(p_ip_header->ip_p == htons(ip_protocol_icmp))
          {
            sr_icmp_hdr_t *p_icmp_header = (sr_icmp_hdr_t *)(p_ip_header + sizeof(sr_ip_hdr_t));
            if((p_icmp_header->icmp_type == ICMP_TYPE_ECHO_REQUEST) && (p_icmp_header->icmp_code == ICMP_CODE_ECHO_REQUEST))
            {
              send_icmp_packet(sr, packet_to_send, len, ICMP_TYPE_ECHO_REPLY, ICMP_CODE_ECHO_REPLY, interface); /* echo reply */
            }
            else
            {
              send_icmp_packet(sr, packet_to_send, len, ICMP_TYPE_UNREACHABLE, ICMP_CODE_PORT_UNREACHABLE, interface); /* port unreachable */
            }
          }
          else
          {
            send_icmp_packet(sr, packet_to_send, len, ICMP_TYPE_UNREACHABLE, ICMP_CODE_PORT_UNREACHABLE, interface); /* port unreachable */
          }
          return;
        }
        cur = cur->next;
      }
    /*Packet isn't for router -> forward*/
    if (sr_arpcache_lookup(&sr->cache, p_ip_header->ip_dst))
    {
      /* forward that bihhh */
    }
    else
    {
      /*queue that bihhhhh */
    }











    /* Find out which entry in the routing table has the longest prefix match with the destination IP address. */

    /*
    Check the ARP cache for the next-hop MAC address corresponding to the nexthop IP. If it's there, send it. Otherwise, send an ARP request for the next-hop IP
    (if one hasn't been sent within the last second), and add the packet to the queue of
    packets waiting on this ARP request. Obviously, this is a very simplified version
    of the forwarding process, and the low-level details follow. For example, if an
    error occurs in any of the above steps, you will have to send an ICMP message
    back to the sender notifying them of an error. You may also get an ARP request
    or reply, which has to interact with the ARP cache correctly. 
    */


    /* TODO: add case for destination net unreachable -> see send_icmp_net_unreachable in sr_arpchace */
    /* TODO: add case for port unreachable -> see send_icmp_port_unreachable in sr_arpcache */
    /* Get Destination IP using ARP */

  }
  else
  {
    printf("Invalid packet type > packet dropped.\n");
    printf("Packet type: 0x%x", packet_type_id);
    return;
  }
  
}/* end sr_handlePacket */



char *best_prefix(struct sr_instance *sr, uint32_t ip_hdr) {

  struct sr_rt *cur = sr->routing_table;
  char best_match[sr_IFACE_NAMELEN];
  uint32_t best_match_mask = 0;
  while (cur) {
    uint32_t cur_mask = cur->mask.s_addr;
    uint32_t cur_addr = cur->dest.s_addr;
    char *cur_if = cur->interface;

    if ((cur_addr & cur_mask) == (ip_hdr & cur_mask)) { /* might need fixing*/
      if (cur_mask > best_match_mask) {
        memcpy(best_match, cur_if, sr_IFACE_NAMELEN);
        best_match_mask = cur_mask;
      }
    }
    cur = cur->next;
  } 
  return best_match;
}
