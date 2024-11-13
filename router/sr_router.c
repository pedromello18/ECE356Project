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
    // invalid length > drop
    return;
  }
  
  struct sr_ethernet_hdr_t *p_ethernet_header = (sr_ethernet_hdr_t *)packet;
  
  // See if this is an ARP or IP packet type
  uint16_t packet_type_id = p_ethernet_header->ether_type;
  if(packet_type_id == ethertype_arp) ///////////// ARP
  {
    sr_arp_hdr_t *p_arp_header = (sr_arp_hdr_t *) packet + 14;
    unsigned short arp_opcode = p_arp_header->ar_op;
    if (arp_opcode == arp_op_request)
    {
      // check my cache and respond if I find it
      uint32_t ip_dest = p_arp_header->ar_tip;
      struct sr_arpentry *entry = sr_arpcache_lookup(ip_dest); // unsure about type
      if(entry)
      {
      //   if entry:
      //  use next_hop_ip->mac mapping in entry to send the packet
      //  free entry
        memcpy(p_ethernet_header->ether_dhost, entry->mac, ETHER_ADDR_LEN);
        memcpy(p_ethernet_header->ether_shost, /* our mac address */, ETHER_ADDR_LEN);
        free(entry);
      }
      else
      {
        // entry not found, broadcast request
        // req = arpcache_queuereq(next_hop_ip, packet, len)
        struct sr_arpreq *arpreq = sr_arpcache_queuereq(&sr->cache, p_ip_header->ip_dst, packet, len, interface);
        handle_arpreq(arpreq);
        free(arpreq);
      }
    }
    else if (arp_opcode == arp_op_reply) 
    {
      // save mapping to arpcache
      sr_arpcache_insert(sr->cache, p_arp_header->ar_sha, p_arp_header->ar_sip);      

      // forward to original sender

    }
  } 
  else if(packet_type_id == ethertype_ip) //////////// IP
  {
    struct sr_ip_hdr_t *p_ip_header = (sr_ip_hdr_t *) packet + 14;
    
  }
  else
  {
    // invalid packet type
    return;
  }
  /////////////////////////////////////////
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
  sr_rt *longest_match_entry = sr.routing_table;
  sr_rt *cur = sr.routing_table;
  while(cur.next != NULL)
  {
    // 
    cur = cur.next;
  }
  // figure out which interface to send to? idk

  // TODO: add case for destination net unreachable
  // TODO: add case for port unreachable

  // Get Destination IP using ARP

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
  struct sr_arpentry *arpentry = sr_arpcache_lookup(&sr.cache, p_ip_header->ip_dst);
  if(arpentry == NULL)
  {
    // mapping not in cache > add to ARP request queue
    sr_arpreq* arpreq = sr_arpcache_queuereq(&sr.cache, p_ip_header->ip_dst, packet, len, interface); // unsure
  }
  else
  {
    // get MAC address from arpentry and put it into packet
    memcpy(p_ethernet_header->ether_dhost, arpentry.mac, 6);
    
    // use routing table to figure out what interface to send to?
    // i think we had to do that earlier

    sr_send_packet(sr, packet, len, /* interface */);
    // free(arpentry)
  }

}/* end sr_ForwardPacket */


