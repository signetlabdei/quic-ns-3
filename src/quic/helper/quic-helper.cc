/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2008 INRIA
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 * Author: Faker Moatamri <faker.moatamri@sophia.inria.fr>
 */

#include "ns3/assert.h"
#include "ns3/log.h"
#include "ns3/object.h"
#include "ns3/names.h"
#include "ns3/ipv4.h"
#include "ns3/ipv6.h"
#include "ns3/packet-socket-factory.h"
#include "ns3/config.h"
#include "ns3/simulator.h"
#include "ns3/string.h"
#include "ns3/net-device.h"
#include "ns3/callback.h"
#include "ns3/node.h"
#include "ns3/node-list.h"
#include "ns3/core-config.h"
#include "ns3/arp-l3-protocol.h"
#include "ns3/internet-stack-helper.h"
#include "quic-helper.h"
#include "ns3/ipv4-global-routing.h"
#include "ns3/ipv4-list-routing-helper.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/ipv6-static-routing-helper.h"
#include "ns3/ipv6-extension.h"
#include "ns3/ipv6-extension-demux.h"
#include "ns3/ipv6-extension-header.h"
#include "ns3/icmpv6-l4-protocol.h"
#include "ns3/global-router-interface.h"
#include "ns3/traffic-control-layer.h"
#include "ns3/quic-socket-factory.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QuicHelper");

//
// Historically, the only context written to ascii traces was the protocol.
// Traces from the protocols include the interface, though.  It is not 
// possible to really determine where an event originated without including
// this.  If you want the additional context information, define 
// INTERFACE_CONTEXT.  If you want compatibility with the old-style traces
// comment it out.
//
#define INTERFACE_CONTEXT

//
// Things are going to work differently here with respect to trace file handling
// than in most places because the Tx and Rx trace sources we are interested in
// are going to multiplex receive and transmit callbacks for all Ipv4 and 
// interface pairs through one callback.  We want packets to or from each 
// distinct pair to go to an individual file, so we have got to demultiplex the
// Ipv4 and interface pair into a corresponding Ptr<PcapFileWrapper> at the 
// callback.
//
// A complication in this situation is that the trace sources are hooked on 
// a protocol basis.  There is no trace source hooked by an Ipv4 and interface
// pair.  This means that if we naively proceed to hook, say, a drop trace
// for a given Ipv4 with interface 0, and then hook for Ipv4 with interface 1
// we will hook the drop trace twice and get two callbacks per event.  What
// we need to do is to hook the event once, and that will result in a single
// callback per drop event, and the trace source will provide the interface
// which we filter on in the trace sink.
// 
// This has got to continue to work properly after the helper has been 
// destroyed; but must be cleaned up at the end of time to avoid leaks. 
// Global maps of protocol/interface pairs to file objects seems to fit the 
// bill.
//

void
QuicHelper::InstallQuic (NodeContainer c) const
{
  NS_LOG_INFO("stack install");
  for (NodeContainer::Iterator i = c.Begin (); i != c.End (); ++i)
    {
      Install (*i);
      NS_LOG_INFO("ok " << *i);
      CreateAndAggregateObjectFromTypeId (*i, "ns3::QuicL4Protocol");

//      Ptr<QuicSocketFactory> factory = CreateObject<QuicSocketFactory> ();
//      factory->SetNode(*i);
//      (*i)->AggregateObject (factory);
    }
}

void
QuicHelper::CreateAndAggregateObjectFromTypeId (Ptr<Node> node, const std::string typeId)
{
  ObjectFactory factory;
  factory.SetTypeId (typeId);
  Ptr<Object> protocol = factory.Create <Object> ();
  node->AggregateObject (protocol);
}

} // namespace ns3
