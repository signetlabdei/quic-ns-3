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
 */

#ifndef QUIC_HELPER_H
#define QUIC_HELPER_H

#include "ns3/node-container.h"
#include "ns3/net-device-container.h"
#include "ns3/packet.h"
#include "ns3/ptr.h"
#include "ns3/object-factory.h"
#include "ns3/ipv4-l3-protocol.h"
#include "ns3/ipv6-l3-protocol.h"
#include "ns3/internet-trace-helper.h"
#include "ns3/internet-stack-helper.h"

namespace ns3 {
/**
 * \defgroup internet Internet
 *
 * This section documents the API of the ns-3 internet module. For a generic functional description, please refer to the ns-3 manual.
 */

/**
 * \ingroup internet
 * \defgroup ipv4Helpers IPv4 Helper classes
 */

/**
 * \ingroup internet
 * \defgroup ipv6Helpers IPv6 Helper classes
 */

/**
 * \ingroup internet
 *
 * \brief aggregate IP/TCP/UDP functionality to existing Nodes.
 *
 * This helper enables pcap and ascii tracing of events in the internet stack
 * associated with a node.  This is substantially similar to the tracing
 * that happens in device helpers, but the important difference is that, well,
 * there is no device.  This means that the creation of output file names will
 * change, and also the user-visible methods will not reference devices and
 * therefore the number of trace enable methods is reduced.
 *
 * Normally we avoid multiple inheritance in ns-3, however, the classes 
 * PcapUserHelperForIpv4 and AsciiTraceUserHelperForIpv4 are
 * treated as "mixins".  A mixin is a self-contained class that
 * encapsulates a general attribute or a set of functionality that
 * may be of interest to many other classes.
 *
 * This class aggregates instances of these objects, by default, to each node:
 *  - ns3::ArpL3Protocol
 *  - ns3::Ipv4L3Protocol
 *  - ns3::Icmpv4L4Protocol
 *  - ns3::Ipv6L3Protocol
 *  - ns3::Icmpv6L4Protocol
 *  - ns3::UdpL4Protocol
 *  - ns3::TrafficControlLayer
 *  - a TCP based on the TCP factory provided
 *  - a PacketSocketFactory
 *  - Ipv4 routing (a list routing object, a global routing object, and a static routing object)
 *  - Ipv6 routing (a static routing object)
 */
class QuicHelper : public InternetStackHelper
{
public:
  /**
   * For each node in the input container, aggregate implementations of the
   * ns3::Ipv4, ns3::Ipv6, ns3::Udp, ns3::Quic, and ns3::Tcp classes.  The program will assert
   * if this method is called on a container with a node that already has
   * an Ipv4 object aggregated to it.
   *
   * \param c NodeContainer that holds the set of nodes on which to install the
   * new stacks.
   */
  void InstallQuic (NodeContainer c) const;

private:
  /**
   * \brief create an object from its TypeId and aggregates it to the node
   * \param node the node
   * \param typeId the object TypeId
   */
  static void CreateAndAggregateObjectFromTypeId (Ptr<Node> node, const std::string typeId);
};

} // namespace ns3

#endif /* QUIC_HELPER_H */
