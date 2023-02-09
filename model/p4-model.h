/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
* Copyright (c) YEAR COPYRIGHTHOLDER
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
* Author:
*/
#ifndef P4_MODEL_H
#define P4_MODEL_H

#include <ns3/ptr.h>
#include <ns3/mac48-address.h>
#include "ns3/log.h"
#include "ns3/object.h"
#include "ns3/packet.h"
#include "ns3/bridge-channel.h"
#include "ns3/node.h"
#include "ns3/enum.h"
#include "ns3/string.h"
#include "ns3/integer.h"
#include "ns3/uinteger.h"
#include "ns3/traced-value.h"
#include <bm/bm_sim/queue.h>
#include <bm/bm_sim/queueing.h>
#include <bm/bm_sim/packet.h>
#include <bm/bm_sim/switch.h>
#include <bm/bm_sim/event_logger.h>
#include <bm/bm_sim/simple_pre_lag.h>
#include <bm/bm_sim/parser.h>
#include <bm/bm_sim/tables.h>
#include <bm/bm_sim/logger.h>
#include <fstream>

#include <memory>
#include <vector>
#include <chrono>
#include "ns3/p4-controller.h"
#include "ns3/p4-net-device.h"
namespace ns3 {

	class P4NetDevice;

	/**
	* \brief A P4 Pipeline Implementation to be wrapped in P4 Device
	*
	* The P4Model is using pipeline implementation provided by
	* `Behavioral Model` (https://github.com/p4lang/behavioral-model).
	* In particular, some internal processing functions and the `switch`
	* class are used. However, the way P4Model processes packets is
	* adapted to the requirements of ns-3.
	*
	* P4Model is initialized along with P4 Device, and expose a public
	* function called receivePacket() to the P4 Device. Whenever P4
	* Device has a packet needing handling, it call receivePacket and
	* wait for this function to return. receivePacket() puts the packet
	* through P4 pipeline.
	*
	* \attention P4Model transform ns::packet to bm::packet, which results
	* loss of metadata. We are currently working on reserving the metadata.
	*
	*/
	class P4Model : public bm::Switch {
	public:
		/**
		* \brief Get the type ID.
		* \return the object TypeId
		*/
		static TypeId GetTypeId(void);

		/**
		* \brief a function from bm which will be called every time a
		* packet is received.
		*
		* Since we are not letting the bm switch really work in a
		* simulation enviornment. Instead we just borrow its processing pipeline,
		* which means this receive_() will never be called, so we just return 0.
		*/
		int receive_(int port_num, const char *buffer, int len) {
			return 0;
		}
		int receive_(port_t port_num, const char *buffer, int len){
			return 0;
		}

		/**
		* \brief a function from bm called to initialize the P4 device.
		*
		* Never called either for the same reason with receive_()
		*/
		void start_and_return_() {
		}

		/**
		 * @brief receive a packet and after process send it out, the p4 device receive 
		 * a ns3 package will convert it into a p4 package, then using P4 pipeline. 
		 * After processed the p4 package will convert back to ns3. Called every time 
		 * there is a packet need processed by P4 Device.
		 * 
		 * @param packetIn ns3::packet comes in
		 * @param inPort 
		 * @param protocol ns3 protocol to send and receive
		 * @param destination ns3 destination for send packet out
		 * @return int 
		 */
		int ReceivePacket(Ptr<ns3::Packet> packetIn, int inPort, uint16_t protocol, Address const &destination);

		/**
		* \brief Initialize the P4 Model
		*
		* We instantiate one P4 Model using a json file compiled from
		* P4 file. Also start the thrift to communicate with the
		* controller.
		* 1. setting the json file to the sw
		* 2. setting the flow table command
		*
		* \TODO We will implement a controller model in the future so
		* a thrift server is not needed to populate table entriea.
		*
		*/
		int init(int argc, char *argv[]);

		/**
		* \brief Define target-specific properties, for example
		* `standard_metadata` and `intrinsic_metadata`
		*/
		P4Model(P4NetDevice* netDevice);

		~P4Model()
		{
			m_pNetDevice = NULL;
			if (m_argParser != NULL)
				delete m_argParser;
		}

		/**
		* \brief configure switch with json file
		*/
		int InitFromCommandLineOptionsLocal(int argc, char *argv[], bm::TargetParserBasic *tp = nullptr);

		/**
		 * @brief Trace the pkts whether will be dropped in bmv2.
		 * And also trace the reason and the info of the drop, for example, 
		 * trace the pkts belongs which queue (priority), or drop pkts 
		 * because the table not match(no dst in network)
		 * 
		 * @param phv 
		 * @return bool false will drop the pkts
		 */
		bool TraceAllDropInBmv2(bm::PHV *phv);

		bool RecordAllDropInfo(int queue_id);

	private:

		/**
		* \brief Transform a ns::packet and a bm::packet
		*
		* To use the P4 pipeline provided by Behavioral Model, input
		* packet must be conform the bm style. Also we preserve the
		* ingress port information here.
		*
		* Called when receive a packet from P4 Device.
		*
		* \param ns3packet A `ns::Packet` instance
		* \return A `bm::Packet` instance transformed from a ns::Packet instance.
		*/
		//struct Bm2PacketAndPort * Ns3ToBmv2(struct Ns3PacketAndPort * ns3Packet);

		/**
		* \brief Transform a bm::packet and a ns::packet
		*
		* Called when putting a packet back to the P4 Device.
		*/
		//struct Ns3PacketAndPort * Bmv2ToNs3(struct Bm2PacketAndPort *);

		int m_pktID = 0;								//!< Packet ID
		TracedValue<int64_t> m_qDropNum_1;        		//!< Number of the pkts drops in 1 queue
		TracedValue<int64_t> m_qDropNum_2;        		//!< Number of the pkts drops in 2 queue
		TracedValue<int64_t> m_qDropNum_3;        		//!< Number of the pkts drops in 3 queue
		TracedValue<int64_t> m_dropNum;					//!< Number of the pkts drops (passive droped)
		using clock = std::chrono::high_resolution_clock;

		bm::TargetParserBasic * m_argParser; 		//!< Structure of parsers

		/**
		* A simple, 2-level, packet replication engine,
		* configurable by the control plane.
		*/
		std::shared_ptr<bm::McSimplePre> m_pre;
		P4NetDevice* m_pNetDevice; 					//!< P4Model's P4NetDevice
	};


} // namespace ns3
#endif // !P4_MODEL_H


