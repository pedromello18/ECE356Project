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

  /* Sanity check the packet (meets minimum length and has correct checksum). */
  if(len - 14 < 21)
  {
    printf("Invalid length > packet dropped.");
    return;
  }
  
  /* See if this is an ARP or IP packet type */
  sr_ethernet_hdr_t *p_ethernet_header = (struct sr_ethernet_hdr_t *)packet;
  uint16_t packet_type_id = p_ethernet_header->ether_type;
  if(packet_type_id == ethertype_arp) /* ARP */
  {
    sr_arp_hdr_t *p_arp_header = (sr_arp_hdr_t *) packet + 14;
    unsigned short arp_opcode = p_arp_header->ar_op;
    if (arp_opcode == arp_op_request)
    {
      /* check my cache and respond if I find it */
      uint32_t ip_dest = p_arp_header->ar_tip;
      struct sr_arpentry *entry = sr_arpcache_lookup(sr->cache, ip_dest); 
      if(entry)
      {
      /*
      if entry:
      use next_hop_ip->mac mapping in entry to send the packet
      free entry
      */   
        memcpy(p_ethernet_header->ether_dhost, entry->mac, ETHER_ADDR_LEN);
        memcpy(p_ethernet_header->ether_shost, /* our mac address */, ETHER_ADDR_LEN);
        free(entry);
      }
      else
      {
        /*
        entry not found, broadcast request
        req = arpcache_queuereq(next_hop_ip, packet, len)
        */
        struct sr_arpreq *arpreq = sr_arpcache_queuereq(&sr->cache, p_arp_header->ar_tip, packet, len, interface);
        handle_arpreq(arpreq);
        free(arpreq);
      }
    }
    else if (arp_opcode == arp_op_reply) 
    {
      /* Cache the entry if the target IP address is one of your router's IP addresses*/
      if(idk)
      {
        sr_arpcache_insert(sr->cache, p_arp_header->ar_sha, p_arp_header->ar_sip);      
      }

      /* forward to original sender */

    }
  } 
  else if(packet_type_id == ethertype_ip) /* IP */
  {
    sr_ip_hdr_t *p_ip_header = (sr_ip_hdr_t *) packet + 14;
    
    uint16_t expected_checksum = cksum(p_ip_header, p_ip_header->ip_len);
    uint16_t received_checksum = p_ip_header->ip_sum;
    if(received_checksum != expected_checksum)
    {
      printf("Checksum detected an error > packet dropped.");
      return;
    }

    /* Decrement the TTL by 1, and recompute the packet checksum over the modified header. */
    uint8_t received_ttl = p_ip_header->ip_ttl
    if(received_ttl == 0)
    {
      /* time exceeded > send ICMP message */
      sr_icmp_hdr_t icmp_hdr;
      icmp_hdr.icmp_type = 11;
      icmp_hdr.icmp_code = 0;
      icmp_hdr.icmp_sum = 0;
      icmp_hdr.icmp_sum = cksum(&icmp_hdr, 32);
      sr_send_packet(/* add arguments in here */)
    }
    p_ip_header->ip_ttl = received_ttl - 1;
    p_ip_header->ip_sum = cksum(p_ip_header, p_ip_header->ip_len); 

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


    /* TODO: add case for destination net unreachable */
    /* TODO: add case for port unreachable */
    /* Get Destination IP using ARP */



  }
  else
  {
    printf("Invalid packet type > packet dropped.");
    return;
  }
  
}/* end sr_handlePacket */

char* best_prefix(struct sr_instance *sr, sr_ip_hdr_t *ip_hdr) {
  /* best_match = null */
  /* best_match_mask = 0 */
  /* for each entry in table: */
  /*  if ((entry & entry_mask) == (packet & packet_mask)) */
  /*    if mask is longer than best_match _mask then update best_mask */
  /* return best_match */
}
