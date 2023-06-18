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
#include "ns3/event-id.h"
#include "ns3/nstime.h"
#include "ns3/simulator.h"
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


//! This class is slightly more advanced than QueueingLogicRL. The difference
//! between the 2 is that this one offers the ability to set several priority
//! queues for each logical queue. Priority queues are numbered from `0` to
//! `nb_priorities` (see NSQueueingLogicPriRL::NSQueueingLogicPriRL()). Priority `0`
//! is the highest priority queue. Each priority queue can have its own rate and
//! its own capacity. Queues will be served in order of priority, until their
//! respective maximum rate is reached. If no maximum rate is set, queues with a
//! high priority can starve lower-priority queues. For example, if the queue
//! with priority `0` always contains at least one element, the other queues
//! will never be served.
//! As for QueueingLogicRL, the write behavior (push_front()) is not blocking:
//! once a logical queue is full, subsequent incoming elements will be dropped
//! until the queue starts draining again.
//! Look at the documentation for QueueingLogic for more information about the
//! template parameters (they are the same).
template <typename T, typename FMap>
class NSQueueingLogicPriRL {
  using MutexType = std::mutex;
  using LockType = std::unique_lock<MutexType>;

 public:
  //! See QueueingLogic::QueueingLogicRL() for an introduction. The difference
  //! here is that each logical queue can receive several priority queues (as
  //! determined by \p nb_priorities, which is set to `2` by default). Each of
  //! these priority queues will initially be able to hold \p capacity
  //! elements. The capacity of each priority queue can be changed later by
  //! using set_capacity(size_t queue_id, size_t priority, size_t c).
  NSQueueingLogicPriRL(size_t nb_workers, size_t capacity,
                     FMap map_to_worker, size_t nb_priorities = 2)
      : nb_workers(nb_workers),
        capacity(capacity),
        workers_info(nb_workers),
        map_to_worker(std::move(map_to_worker)),
        nb_priorities(nb_priorities) { }

  //! If priority queue \p priority of logical queue \p queue_id is full, the
  //! function will return `0` immediately. Otherwise, \p item will be copied to
  //! the queue and the function will return `1`. If \p queue_id or \p priority
  //! are incorrect, an exception of type std::out_of_range will be thrown (same
  //! if the FMap object provided to the constructor does not behave correctly).
  int push_front(size_t queue_id, size_t priority, const T &item) {
    size_t worker_id = map_to_worker(queue_id);
    LockType lock(mutex);
    auto &q_info = get_queue(queue_id);
    auto &w_info = workers_info.at(worker_id);
    auto &q_info_pri = q_info.at(priority);
    if (q_info_pri.size >= q_info_pri.capacity) return 0;
    q_info_pri.last_sent = get_next_tp(q_info_pri);
    w_info.queues[priority].emplace(
        item, queue_id, q_info_pri.last_sent, w_info.wrapping_counter++);
    q_info_pri.size++;
    q_info.size++;
    w_info.size++;
    w_info.q_not_empty.notify_one();
    return 1;
  }

  int push_front(size_t queue_id, const T &item) {
    return push_front(queue_id, 0, item);
  }

  //! Same as push_front(size_t queue_id, size_t priority, const T &item), but
  //! \p item is moved instead of copied.
  int push_front(size_t queue_id, size_t priority, T &&item) {
    size_t worker_id = map_to_worker(queue_id);
    LockType lock(mutex);
    auto &q_info = get_queue(queue_id);
    auto &w_info = workers_info.at(worker_id);
    auto &q_info_pri = q_info.at(priority);
    if (q_info_pri.size >= q_info_pri.capacity) return 0;
    q_info_pri.last_sent = get_next_tp(q_info_pri);
    w_info.queues[priority].emplace(
        std::move(item),
        queue_id,
        q_info_pri.last_sent,
        w_info.wrapping_counter++);
    q_info_pri.size++;
    q_info.size++;
    w_info.size++;
    w_info.q_not_empty.notify_one();
    return 1;
  }

  int push_front(size_t queue_id, T &&item) {
    return push_front(queue_id, 0, std::move(item));
  }

  //! Retrieves an element for the worker thread indentified by \p worker_id and
  //! moves it to \p pItem. The id of the logical queue which contained this
  //! element is copied to \p queue_id and the priority value of the served
  //! queue is copied to \p priority.
  //! Elements are retrieved according to the priority queue they are in
  //! (highest priorities, i.e. lowest priority values, are served first). Once
  //! a given priority queue reaches its maximum rate, the next queue is served.
  //! If no elements are available (either the queues are empty or they have
  //! exceeded their rate already), the function will block.
  void pop_back(size_t worker_id, size_t *queue_id, size_t *priority,
                T *pItem) {
    LockType lock(mutex);
    auto &w_info = workers_info.at(worker_id);
    MyQ *queue = nullptr;
    size_t pri;
    while (true) {
      if (w_info.size == 0) {
		// w_info.q_not_empty.wait(lock); 空队列，等到锁状态变化(加入pkts)
		// 将会取出空值，但是检测步骤交给后续处理
        return;
      } else {
		// 队列中有pkt
        Time now = Simulator::Now();
        Time next = now + Seconds (10); // set 10s as the max interval for one packet process.
        for (pri = 0; pri < nb_priorities; pri++) {
          auto &q = w_info.queues[pri];
          if (q.size() == 0) continue;
          if (q.top().send <= now) {
            queue = &q;
            break;
          }
          next = (next < q.top().send) ? next : q.top().send;
        }
        if (queue) break;
		// 此时队列又为空队列，等待锁状态变化(加入pkts)
		// 将会取出空值，但是检测步骤交给后续处理
        return;
      }
    }
    *queue_id = queue->top().queue_id;
    *priority = pri;
    // TODO(antonin): improve / document this
    // http://stackoverflow.com/questions/20149471/move-out-element-of-std-priority-queue-in-c11
    *pItem = std::move(const_cast<QE &>(queue->top()).e);
    queue->pop();
    auto &q_info = get_queue_or_throw(*queue_id);
    auto &q_info_pri = q_info.at(*priority);
    q_info_pri.size--;
    q_info.size--;
    w_info.size--;
  }

  //! Same as
  //! pop_back(size_t worker_id, size_t *queue_id, size_t *priority, T *pItem),
  //! but the priority of the popped element is discarded.
  void pop_back(size_t worker_id, size_t *queue_id, T *pItem) {
    size_t priority;
    return pop_back(worker_id, queue_id, &priority, pItem);
  }

  //! @copydoc QueueingLogic::size
  //! The occupancies of all the priority queues for this logical queue are
  //! added.
  size_t size(size_t queue_id) const {
    LockType lock(mutex);
    auto it = queues_info.find(queue_id);
    if (it == queues_info.end()) return 0;
    auto &q_info = it->second;
    return q_info.size;
  }

  //! Get the occupancy of priority queue \p priority for logical queue with id
  //! \p queue_id.
  size_t size(size_t queue_id, size_t priority) const {
    LockType lock(mutex);
    auto it = queues_info.find(queue_id);
    if (it == queues_info.end()) return 0;
    auto &q_info = it->second;
    auto &q_info_pri = q_info.at(priority);
    return q_info_pri.size;
  }

  //! Set the capacity of all the priority queues for logical queue \p queue_id
  //! to \p c elements.
  void set_capacity(size_t queue_id, size_t c) {
    LockType lock(mutex);
    for_each_q(queue_id, SetCapacityFn(c));
  }

  //! Set the capacity of priority queue \p priority for logical queue \p
  //! queue_id to \p c elements.
  void set_capacity(size_t queue_id, size_t priority, size_t c) {
    LockType lock(mutex);
    for_one_q(queue_id, priority, SetCapacityFn(c));
  }

  //! Set the capacity of all the priority queues of all logical queues to \p c
  //! elements.
  void set_capacity_for_all(size_t c) {
    LockType lock(mutex);
    for (auto &p : queues_info) for_each_q(p.first, SetCapacityFn(c));
    capacity = c;
  }

  //! Set the maximum rate of all the priority queues for logical queue \p
  //! queue_id to \p pps. \p pps is expressed in "number of elements per
  //! second". Until this function is called, there will be no rate limit for
  //! the queue. The same behavior (no rate limit) can be achieved by calling
  //! this method with a rate of 0.
  void set_rate(size_t queue_id, uint64_t pps) {
    LockType lock(mutex);
    for_each_q(queue_id, SetRateFn(pps));
  }

  //! Same as set_rate(size_t queue_id, uint64_t pps) but only applies to the
  //! given priority queue.
  void set_rate(size_t queue_id, size_t priority, uint64_t pps) {
    LockType lock(mutex);
    for_one_q(queue_id, priority, SetRateFn(pps));
  }

  //! Set the rate of all the priority queues of all logical queues to \p pps.
  void set_rate_for_all(uint64_t pps) {
    LockType lock(mutex);
    for (auto &p : queues_info) for_each_q(p.first, SetRateFn(pps));
    queue_rate_pps = pps;
  }

  //! Deleted copy constructor
  NSQueueingLogicPriRL(const NSQueueingLogicPriRL &) = delete;
  //! Deleted copy assignment operator
  NSQueueingLogicPriRL &operator =(const NSQueueingLogicPriRL &) = delete;

  //! Deleted move constructor
  NSQueueingLogicPriRL(NSQueueingLogicPriRL &&) = delete;
  //! Deleted move assignment operator
  NSQueueingLogicPriRL &&operator =(NSQueueingLogicPriRL &&) = delete;

 private:
 
  static constexpr Time rate_to_time(uint64_t pps) {
    // 计算中间的时间间隔
    return (pps == 0) ?
        Seconds (0) : Seconds (static_cast<double>(1. / static_cast<double>(pps)));
  }

  struct QE {
    QE(T e, size_t queue_id, const Time &send, size_t id)
        : e(std::move(e)), queue_id(queue_id), send(send), id(id) { }

    T e;
    size_t queue_id;
    Time send;
    size_t id;
  };

  struct QEComp {
    bool operator()(const QE &lhs, const QE &rhs) const {
      return (lhs.send == rhs.send) ? lhs.id > rhs.id : lhs.send > rhs.send;
    }
  };

  using MyQ = std::priority_queue<QE, std::deque<QE>, QEComp>;

  struct QueueInfoPri {
    QueueInfoPri(size_t capacity, uint64_t queue_rate_pps)
        : capacity(capacity),
          queue_rate_pps(queue_rate_pps),
          pkt_delay_time(rate_to_time(queue_rate_pps)),
          last_sent(Simulator::Now()) { }

    size_t size{0};
    size_t capacity;
    uint64_t queue_rate_pps;
    Time pkt_delay_time;
    Time last_sent;
  };

  struct QueueInfo : public std::vector<QueueInfoPri> {
    QueueInfo(size_t capacity, uint64_t queue_rate_pps, size_t nb_priorities)
        : std::vector<QueueInfoPri>(
              nb_priorities, QueueInfoPri(capacity, queue_rate_pps)) { }

    size_t size{0};
  };

  struct WorkerInfo {
    mutable std::condition_variable q_not_empty{};
    size_t size{0};
    std::array<MyQ, 32> queues;
    size_t wrapping_counter{0};
  };

  QueueInfo &get_queue(size_t queue_id) {
    auto it = queues_info.find(queue_id);
    if (it != queues_info.end()) return it->second;
    auto p = queues_info.emplace(
        queue_id, QueueInfo(capacity, queue_rate_pps, nb_priorities));
    return p.first->second;
  }

  const QueueInfo &get_queue_or_throw(size_t queue_id) const {
    return queues_info.at(queue_id);
  }

  QueueInfo &get_queue_or_throw(size_t queue_id) {
    return queues_info.at(queue_id);
  }

  Time get_next_tp(const  QueueInfoPri &q_info_pri) {
    // 计算出下一步应该发送的时间
    return (Simulator::Now() > q_info_pri.last_sent + q_info_pri.pkt_delay_time) ? 
            Simulator::Now() : q_info_pri.last_sent + q_info_pri.pkt_delay_time;
  }

  template <typename Function>
  Function for_each_q(size_t queue_id, Function fn) {
    auto &q_info = get_queue(queue_id);
    for (auto &q_info_pri : q_info) fn(q_info_pri);
    return fn;
  }

  template <typename Function>
  Function for_one_q(size_t queue_id, size_t priority, Function fn) {
    auto &q_info = get_queue(queue_id);
    auto &q_info_pri = q_info.at(priority);
    fn(q_info_pri);
    return fn;
  }

  struct SetCapacityFn {
    explicit SetCapacityFn(size_t c)
        : c(c) { }

    void operator ()(QueueInfoPri &info) const {  // NOLINT(runtime/references)
      info.capacity = c;
    }

    size_t c;
  };

  struct SetRateFn {
    explicit SetRateFn(uint64_t pps)
        : pps(pps) {
      pkt_delay_time = rate_to_time(pps);
    }

    void operator ()(QueueInfoPri &info) const {  // NOLINT(runtime/references)
      info.queue_rate_pps = pps;
      info.pkt_delay_time = pkt_delay_time;
    }

    uint64_t pps;
    Time pkt_delay_time;
  };

  mutable MutexType mutex;
  size_t nb_workers;
  size_t capacity;  // default capacity
  uint64_t queue_rate_pps{0};  // default rate
  std::unordered_map<size_t, QueueInfo> queues_info{};
  std::vector<WorkerInfo> workers_info{};
  std::vector<MyQ> queues{};
  FMap map_to_worker;
  size_t nb_priorities;
};

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
		int p4_switch_ID;											//!< the total drop packages number
		std::map<int64_t, DelayJitterEstimationTimestampTag> tag_map;
		
		// time event for thread local
		size_t worker_id;											//!< worker_id = threads_id, here only one
		EventId m_egressTimerEvent;              					//!< The timer event ID [Egress]
		Time m_egressTimeReference;        	  						//!< Desired time between timer event triggers
		EventId m_transmitTimerEvent;              					//!< The timer event ID [Transfer]
		Time m_transmitTimeReference;        	  					//!< Desired time between timer event triggers

    mutable std::mutex m_tag_queue_mutex;

    // tracing with simple number count
		int tracing_control_loop_num;
		int64_t tracing_ingress_total_pkts;
		int64_t tracing_ingress_drop;
		int64_t tracing_egress_total_pkts;
		int64_t tracing_egress_drop;
		int64_t tracing_total_in_pkts;
		int64_t tracing_total_out_pkts;
    
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

		// returns the packet id of most recently received packet. Not thread-safe.
		static packet_id_t get_packet_id() {
			return packet_id - 1;
		}

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
	
	private:
		static constexpr size_t nb_egress_threads = 1u; // 4u default in bmv2, but in ns-3 make sure safe
		static packet_id_t packet_id;

		class MirroringSessions;

		class InputBuffer;
		// template <typename T, typename FMap> class NSQueueingLogicPriRL;

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
   void ingress_pipeline(std::unique_ptr<bm::Packet> packet);
		void egress_thread(size_t worker_id);
		void transmit_thread();

		void RunEgressTimerEvent ();
		void RunTransmitTimerEvent ();

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
		NSQueueingLogicPriRL<std::unique_ptr<bm::Packet>, EgressThreadMapper> egress_buffers;
		bm::Queue<std::unique_ptr<bm::Packet> > output_buffer;
		TransmitFn my_transmit_fn;
		std::shared_ptr<McSimplePreLAG> pre;
		std::chrono::high_resolution_clock::time_point start;
		bool with_queueing_metadata{false};
		std::unique_ptr<MirroringSessions> mirroring_sessions;

		int64_t m_pktID = 0;								//!< Packet ID
		int64_t m_re_pktID = 0;								//!< Receiver side Packet ID

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


