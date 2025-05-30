/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
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
 * Author: PengKuang <kphf1995cm@outlook.com>
 */

/*
 *          Network topology discription
 *          _________________________
 *          |                        |
 *          |        switch          |      
 *          |                        |
 *          |________________________|
 *            |                     |  
 *           h0(dst)             h1(src)
 *     ip:10.1.1.1               10.1.1.2
 *     mac:00:00:00:00:00:01     00:00:00:00:00:07
 *     UdpEchoServer             UdpEchoClient
 *
*/

#include <iostream>
#include <fstream>

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/applications-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/p4-helper.h"
#include "ns3/v4ping-helper.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("P4Test");

int main (int argc, char *argv[]) {
    int p4 = 0;

    LogComponentEnable ("P4Test", LOG_LEVEL_LOGIC);
    LogComponentEnable ("P4Helper", LOG_LEVEL_LOGIC);
    LogComponentEnable ("P4NetDevice", LOG_LEVEL_LOGIC);

    CommandLine cmd;
    cmd.Parse (argc, argv);

    NS_LOG_INFO ("Create nodes.");
    NodeContainer nodes;
    nodes.Create(2);

    NodeContainer csmaSwitch;
    csmaSwitch.Create(1);

    NS_LOG_INFO ("Build Topology");
    CsmaHelper csma;
    csma.SetChannelAttribute ("DataRate", DataRateValue (5000000));
    csma.SetChannelAttribute ("Delay", TimeValue (MilliSeconds (2)));

    NetDeviceContainer terminalDevices;
    NetDeviceContainer switchDevices;

    for (int i = 0; i < 2; i ++) {
        NetDeviceContainer link = csma.Install(NodeContainer(nodes.Get(i), csmaSwitch.Get(0)));
        terminalDevices.Add(link.Get(0));
        switchDevices.Add(link.Get(1));
    }

    Ptr<Node> switchNode = csmaSwitch.Get(0);

    if (p4) {
        P4Helper bridge;
        NS_LOG_INFO("P4 bridge established");
        bridge.Install (switchNode, switchDevices);
    } else {
       BridgeHelper bridge;
       bridge.Install (switchNode, switchDevices);
    }

    InternetStackHelper internet;
    internet.Install (nodes);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase ("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer addresses = ipv4.Assign(terminalDevices);

    // Create Applications
    NS_LOG_INFO ("Create Applications.");
    UdpEchoServerHelper echoServer (9);

    ApplicationContainer serverApps = echoServer.Install(nodes.Get(0));
    serverApps.Start (Seconds(1.0));
    serverApps.Stop (Seconds(10.0));

    UdpEchoClientHelper echoClient (addresses.GetAddress(0), 9);
    echoClient.SetAttribute ("MaxPackets", UintegerValue(1));
    echoClient.SetAttribute ("Interval", TimeValue (Seconds (1.0)));
    echoClient.SetAttribute ("PacketSize", UintegerValue (1024));

    ApplicationContainer clientApps = echoClient.Install (nodes.Get(1));
    clientApps.Start (Seconds (2.0));
    clientApps.Stop (Seconds (10.0));

    Packet::EnablePrinting ();

    Simulator::Run ();
    Simulator::Destroy ();
    return 0;
}
