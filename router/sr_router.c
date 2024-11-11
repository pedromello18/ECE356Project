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

  // Sanity check the packet (meets minimum length and has correct checksum).
  if(len - 14 < 21)
  {
    // invalid length > drop that shit
    return;
  }
  
  struct sr_ip_hdr_t *p_ip_header = (sr_ip_hdr_t *)packet + 14;
  uint16_t expected_checksum = cksum(p_ip_header, len-14);
  uint16_t received_checksum = p_ip_header->ip_sum;

  if(received_checksum != expected_checksum)
  {
    // error detected > drop that shit
    return;
  }

  // Decrement the TTL by 1, and recompute the packet checksum over the modified header.
  uint8_t received_ttl = p_ip_header->ip_ttl
  if(received_ttl == 0)
  {
    // time exceeded > send ICMP message
    struct sr_icmp_hdr_t icmp_hdr;
    icmp_hdr.icmp_type = 11;
    icmp_hdr.icmp_code = 0;
    icmp_hdr.icmp_sum = 0;
    icmp_hdr.icmp_sum = cksum(&icmp_hdr, 32);
    sr_send_packet(/* add arguments in here */)
  }
  ip_header[8] = received_ttl - 1;
  uint16_t new_checksum = cksum(ip_header, len - 14); 
  ip_header[10] = new_checksum & 0xFF;
  ip_header[11] = (new_checksum >> 8) & 0xFF;

  // Find out which entry in the routing table has the longest prefix match with the destination IP address.
  sr_rt *longest_match_entry = this.routing_table;
  sr_rt *cur = this.routing_table;
  while(cur.next != NULL)
  {
    // 
    cur = cur.next;
  }
  // TODO: add case for destination net unreachable
  // TODO: add case for port unreachable

  // Get Destination IP using ARP

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
  struct sr_arpentry *arpentry = sr_arpcache_lookup(&this.cache, p_ip_header->ip_dst);
  if(arpentry == NULL)
  {
    // mapping not in cache > send ARP request
  }
  else
  {
    uint32_t dest_ip_addr = arpentry->ip;

  }

/*
  Check the ARP cache for the next-hop MAC address corresponding to the nexthop IP. If it's there, send it. Otherwise, send an ARP request for the next-hop IP
  (if one hasn't been sent within the last second), and add the packet to the queue of
  packets waiting on this ARP request. Obviously, this is a very simplified version
  of the forwarding process, and the low-level details follow. For example, if an
  error occurs in any of the above steps, you will have to send an ICMP message
  back to the sender notifying them of an error. You may also get an ARP request
  or reply, which has to interact with the ARP cache correctly.
*/

}/* end sr_ForwardPacket */


