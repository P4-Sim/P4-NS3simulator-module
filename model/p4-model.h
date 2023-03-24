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
#include "ns3/delay-jitter-estimation.h"
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
#include <mutex>
#include <memory>
#include <vector>
#include <chrono>
#include <functional>
#include "ns3/p4-controller.h"
#include "ns3/p4-net-device.h"

// TODO(antonin)
// experimental support for priority queueing
// to enable it, uncomment this flag
// you can also choose the field from which the priority value will be read, as
// well as the number of priority queues per port
// PRIORITY 0 IS THE LOWEST PRIORITY
#define SSWITCH_PRIORITY_QUEUEING_SRC "intrinsic_metadata.priority"

using ts_res = std::chrono::microseconds;
using std::chrono::duration_cast;
using ticks = std::chrono::nanoseconds;

using bm::Switch;
using bm::Queue;
using bm::Packet;
using bm::PHV;
using bm::Parser;
using bm::Deparser;
using bm::Pipeline;
using bm::McSimplePreLAG;
using bm::Field;
using bm::FieldList;
using bm::packet_id_t;
using bm::p4object_id_t;

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
class P4Model : public Switch {
	public:
		// P4Model(P4NetDevice* netDevice);
		
		static TypeId GetTypeId(void);

		std::vector<Address> destination_list;						//!< list for address, using by index
		int address_num;											//!< index of address.
		int p4_switch_ID;
		std::queue<std::unique_ptr<bm::Packet>> bm_queue;			//!< SYNC infomation Queue
		std::queue<std::unique_ptr<bm::Packet>> re_bm_queue;		//!< re_bm_queue for saving pkts from bm_queue

		std::map<int, DelayJitterEstimationTimestampTag> tag_map;

		mutable std::mutex m_mutex;
		mutable std::mutex m_queue_mutex;

		int ReceivePacketOld(Ptr<ns3::Packet> packetIn, int inPort,
    		uint16_t protocol, Address const& destination);

		void SendNs3PktsWithCheckP4(std::string proto1, std::string proto2,
		std::string dest1, std::string dest2, bool traceDrop);

		// with bmv2 simple-switch
		using mirror_id_t = int;
		using TransmitFn = std::function<void(port_t, packet_id_t,
												const char *, int)>;
		using clock = std::chrono::high_resolution_clock; // redeclaration

		struct MirroringSessionConfig {
			port_t egress_port;
			bool egress_port_valid;
			unsigned int mgid;
			bool mgid_valid;
		};

		static constexpr port_t default_drop_port = 511;
		static constexpr size_t default_nb_queues_per_port = 8;		

	public:
		// by default, swapping is off
		P4Model(P4NetDevice* netDevice, 
				bool enable_swap = false,
				port_t drop_port = default_drop_port,
				size_t nb_queues_per_port = default_nb_queues_per_port);

		~P4Model();	

		int receive_(port_t port_num, const char *buffer, int len) override;
	
		void start_and_return_() override;

		void reset_target_state_() override;

		void swap_notify_() override;

		bool mirroring_add_session(mirror_id_t mirror_id,
									const MirroringSessionConfig &config);

		bool mirroring_delete_session(mirror_id_t mirror_id);

		bool mirroring_get_session(mirror_id_t mirror_id,
                             MirroringSessionConfig *config) const;
		int set_egress_priority_queue_depth(size_t port, size_t priority,
                                      const size_t depth_pkts);
		int set_egress_queue_depth(size_t port, const size_t depth_pkts);
		int set_all_egress_queue_depths(const size_t depth_pkts);

		int set_egress_priority_queue_rate(size_t port, size_t priority,
											const uint64_t rate_pps);
		int set_egress_queue_rate(size_t port, const uint64_t rate_pps);
		int set_all_egress_queue_rates(const uint64_t rate_pps);

		// returns the number of microseconds elapsed since the switch started
		uint64_t get_time_elapsed_us() const;

		// returns the number of microseconds elasped since the clock's epoch
		uint64_t get_time_since_epoch_us() const;

		// returns the packet id of most recently received packet. Not thread-safe.
		static packet_id_t get_packet_id() {
			return packet_id - 1;
		}
		void set_transmit_fn(TransmitFn fn);

		port_t get_drop_port() const {
			return drop_port;
		}

		P4Model(const P4Model &) = delete;
		P4Model &operator =(const P4Model &) = delete;
		P4Model(P4Model &&) = delete;
		P4Model &&operator =(P4Model &&) = delete;

		// ns3-p4
		int ReceivePacket(Ptr<ns3::Packet> packetIn, int inPort, uint16_t protocol, Address const &destination);
		int init(int argc, char *argv[]);

		/**
		* \brief configure switch with json file
		*/
		int InitFromCommandLineOptionsLocal(int argc, char *argv[], bm::TargetParserBasic *tp = nullptr);

		/*tracing*/
		bool TraceAllDropInBmv2(bm::PHV *phv);
		bool RecordAllDropInfo(int queue_id);
	
	private:
		static constexpr size_t nb_egress_threads = 4u; // 4u default in bmv2, but in ns-3 make sure safe
		static packet_id_t packet_id;

		class MirroringSessions;

		class InputBuffer;

		enum PktInstanceType {
			PKT_INSTANCE_TYPE_NORMAL,
			PKT_INSTANCE_TYPE_INGRESS_CLONE,
			PKT_INSTANCE_TYPE_EGRESS_CLONE,
			PKT_INSTANCE_TYPE_COALESCED,
			PKT_INSTANCE_TYPE_RECIRC,
			PKT_INSTANCE_TYPE_REPLICATION,
			PKT_INSTANCE_TYPE_RESUBMIT,
		};

		struct EgressThreadMapper {
			explicit EgressThreadMapper(size_t nb_threads)
				: nb_threads(nb_threads) { }

			size_t operator()(size_t egress_port) const {
			return egress_port % nb_threads;
			}

			size_t nb_threads;
		};

	private:
		void ingress_thread();
		void egress_thread(size_t worker_id);
		void transmit_thread();

		ts_res get_ts() const;

		// TODO(antonin): switch to pass by value?
		void enqueue(port_t egress_port, std::unique_ptr<bm::Packet> &&packet);

		void copy_field_list_and_set_type(
			const std::unique_ptr<bm::Packet> &packet,
			const std::unique_ptr<bm::Packet> &packet_copy,
			PktInstanceType copy_type, p4object_id_t field_list_id);

		void check_queueing_metadata();

		void multicast(bm::Packet *packet, unsigned int mgid);
	
	private:
		port_t drop_port;
		std::vector<std::thread> threads_;
		std::unique_ptr<InputBuffer> input_buffer;
		// for these queues, the write operation is non-blocking and we drop the
		// packet if the queue is full
		size_t nb_queues_per_port;
		bm::QueueingLogicPriRL<std::unique_ptr<bm::Packet>, EgressThreadMapper>
		egress_buffers;
		bm::Queue<std::unique_ptr<bm::Packet> > output_buffer;
		TransmitFn my_transmit_fn;
		std::shared_ptr<McSimplePreLAG> pre;
		std::chrono::high_resolution_clock::time_point start;
		bool with_queueing_metadata{false};
		std::unique_ptr<MirroringSessions> mirroring_sessions;

		int m_pktID = 0;								//!< Packet ID
		int m_re_pktID = 0;
		TracedValue<int64_t> m_qDropNum_1;        		//!< Number of the pkts drops in 1 queue
		TracedValue<int64_t> m_qDropNum_2;        		//!< Number of the pkts drops in 2 queue
		TracedValue<int64_t> m_qDropNum_3;        		//!< Number of the pkts drops in 3 queue
		TracedValue<int64_t> m_dropNum;					//!< Number of the pkts drops (passive droped)

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


