/* Copyright 2013-present Barefoot Networks, Inc.
 * Copyright 2021 VMware, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Antonin Bas
 *
 */

#include <bm/bm_sim/_assert.h>
#include <bm/bm_sim/logger.h>
#include <bm/bm_sim/parser.h>
#include <bm/bm_sim/tables.h>

#include <unistd.h>

#include <condition_variable>
#include <deque>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>

#include "register_access.h"
#include "simple_switch.h"

namespace {

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
        w_info.q_not_empty.wait(lock);
      } else {
        auto now = clock::now(); // Time now = Simulator::Now()
        auto next = clock::time_point::max(); // Time next = now + Seconds (10); // set 10s as the max interval for one packet process.
        for (pri = 0; pri < nb_priorities; pri++) {
          auto &q = w_info.queues[pri];
          if (q.size() == 0) continue;
          if (q.top().send <= now) {
            queue = &q;
            break;
          }
          next = std::min(next, q.top().send);
        }
        if (queue) break;
        w_info.q_not_empty.wait_until(lock, next);
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
        Seconds (0) : Seconds (<double>(1. /pss));
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
    return std::max(Simulator::Now(),
                    q_info_pri.last_sent + q_info_pri.pkt_delay_time);
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

struct hash_ex {
    uint32_t operator()(const char* buf, size_t s) const
    {
        const uint32_t p = 16777619;
        uint32_t hash = 2166136261;

        for (size_t i = 0; i < s; i++)
            hash = (hash ^ buf[i]) * p;

        hash += hash << 13;
        hash ^= hash >> 7;
        hash += hash << 3;
        hash ^= hash >> 17;
        hash += hash << 5;
        return static_cast<uint32_t>(hash);
    }
};

struct bmv2_hash {
    uint64_t operator()(const char* buf, size_t s) const
    {
        return bm::hash::xxh64(buf, s);
    }
};

} // namespace

// if REGISTER_HASH calls placed in the anonymous namespace, some compiler can
// give an unused variable warning
REGISTER_HASH(hash_ex);
REGISTER_HASH(bmv2_hash);

extern int import_primitives(SimpleSwitch* simple_switch);

packet_id_t SimpleSwitch::packet_id = 0;

class SimpleSwitch::MirroringSessions {
public:
    bool add_session(mirror_id_t mirror_id,
        const MirroringSessionConfig& config)
    {
        Lock lock(mutex);
        if (0 <= mirror_id && mirror_id <= RegisterAccess::MAX_MIRROR_SESSION_ID) {
            sessions_map[mirror_id] = config;
            return true;
        } else {
            bm::Logger::get()->error("mirror_id out of range. No session added.");
            return false;
        }
    }

    bool delete_session(mirror_id_t mirror_id)
    {
        Lock lock(mutex);
        if (0 <= mirror_id && mirror_id <= RegisterAccess::MAX_MIRROR_SESSION_ID) {
            return sessions_map.erase(mirror_id) == 1;
        } else {
            bm::Logger::get()->error("mirror_id out of range. No session deleted.");
            return false;
        }
    }

    bool get_session(mirror_id_t mirror_id,
        MirroringSessionConfig* config) const
    {
        Lock lock(mutex);
        auto it = sessions_map.find(mirror_id);
        if (it == sessions_map.end())
            return false;
        *config = it->second;
        return true;
    }

private:
    using Mutex = std::mutex;
    using Lock = std::lock_guard<Mutex>;

    mutable std::mutex mutex;
    std::unordered_map<mirror_id_t, MirroringSessionConfig> sessions_map;
};

// Arbitrates which packets are processed by the ingress thread. Resubmit and
// recirculate packets go to a high priority queue, while normal packets go to a
// low priority queue. We assume that starvation is not going to be a problem.
// Resubmit packets are dropped if the queue is full in order to make sure the
// ingress thread cannot deadlock. We do the same for recirculate packets even
// though the same argument does not apply for them. Enqueueing normal packets
// is blocking (back pressure is applied to the interface).
class SimpleSwitch::InputBuffer {
public:
    enum class PacketType {
        NORMAL,
        RESUBMIT,
        RECIRCULATE,
        SENTINEL // signal for the ingress thread to terminate
    };

    InputBuffer(size_t capacity_hi, size_t capacity_lo)
        : capacity_hi(capacity_hi)
        , capacity_lo(capacity_lo)
    {
    }

    int push_front(PacketType packet_type, std::unique_ptr<Packet>&& item)
    {
        switch (packet_type) {
        case PacketType::NORMAL:
            return push_front(&queue_lo, capacity_lo, &cvar_can_push_lo,
                std::move(item), true);
        case PacketType::RESUBMIT:
        case PacketType::RECIRCULATE:
            return push_front(&queue_hi, capacity_hi, &cvar_can_push_hi,
                std::move(item), false);
        case PacketType::SENTINEL:
            return push_front(&queue_hi, capacity_hi, &cvar_can_push_hi,
                std::move(item), true);
        }
        _BM_UNREACHABLE("Unreachable statement");
        return 0;
    }

    void pop_back(std::unique_ptr<Packet>* pItem)
    {
        Lock lock(mutex);
        cvar_can_pop.wait(
            lock, [this] { return (queue_hi.size() + queue_lo.size()) > 0; });
        // give higher priority to resubmit/recirculate queue
        if (queue_hi.size() > 0) {
            *pItem = std::move(queue_hi.back());
            queue_hi.pop_back();
            lock.unlock();
            cvar_can_push_hi.notify_one();
        } else {
            *pItem = std::move(queue_lo.back());
            queue_lo.pop_back();
            lock.unlock();
            cvar_can_push_lo.notify_one();
        }
    }

private:
    using Mutex = std::mutex;
    using Lock = std::unique_lock<Mutex>;
    using QueueImpl = std::deque<std::unique_ptr<Packet>>;

    int push_front(QueueImpl* queue, size_t capacity,
        std::condition_variable* cvar,
        std::unique_ptr<Packet>&& item, bool blocking)
    {
        Lock lock(mutex);
        while (queue->size() == capacity) {
            if (!blocking)
                return 0;
            cvar->wait(lock);
        }
        queue->push_front(std::move(item));
        lock.unlock();
        cvar_can_pop.notify_one();
        return 1;
    }

    mutable std::mutex mutex;
    mutable std::condition_variable cvar_can_push_hi;
    mutable std::condition_variable cvar_can_push_lo;
    mutable std::condition_variable cvar_can_pop;
    size_t capacity_hi;
    size_t capacity_lo;
    QueueImpl queue_hi;
    QueueImpl queue_lo;
};

SimpleSwitch::SimpleSwitch(bool enable_swap, port_t drop_port,
    size_t nb_queues_per_port)
    : Switch(enable_swap)
    , drop_port(drop_port)
    , input_buffer(new InputBuffer(
          1024 /* normal capacity */, 1024 /* resubmit/recirc capacity */))
    , nb_queues_per_port(nb_queues_per_port)
    , egress_buffers(nb_egress_threads,
          64, EgressThreadMapper(nb_egress_threads),
          nb_queues_per_port)
    , output_buffer(128)
    ,
    // cannot use std::bind because of a clang bug
    // https://stackoverflow.com/questions/32030141/is-this-incorrect-use-of-stdbind-or-a-compiler-bug
    my_transmit_fn([this](port_t port_num, packet_id_t pkt_id,
                       const char* buffer, int len) {
        _BM_UNUSED(pkt_id);
        this->transmit_fn(port_num, buffer, len);
    })
    , pre(new McSimplePreLAG())
    , start(clock::now())
    , mirroring_sessions(new MirroringSessions())
{
    add_component<McSimplePreLAG>(pre);

    add_required_field("standard_metadata", "ingress_port");
    add_required_field("standard_metadata", "packet_length");
    add_required_field("standard_metadata", "instance_type");
    add_required_field("standard_metadata", "egress_spec");
    add_required_field("standard_metadata", "egress_port");

    force_arith_header("standard_metadata");
    force_arith_header("queueing_metadata");
    force_arith_header("intrinsic_metadata");

    import_primitives(this);
}

int SimpleSwitch::receive_(port_t port_num, const char* buffer, int len)
{
    // we limit the packet buffer to original size + 512 bytes, which means we
    // cannot add more than 512 bytes of header data to the packet, which should
    // be more than enough
    auto packet = new_packet_ptr(port_num, packet_id++, len,
        bm::PacketBuffer(len + 512, buffer, len));

    BMELOG(packet_in, *packet);

    PHV* phv = packet->get_phv();
    // many current P4 programs assume this
    // it is also part of the original P4 spec
    phv->reset_metadata();
    RegisterAccess::clear_all(packet.get());

    // setting standard metadata

    phv->get_field("standard_metadata.ingress_port").set(port_num);
    // using packet register 0 to store length, this register will be updated for
    // each add_header / remove_header primitive call
    packet->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX, len);
    phv->get_field("standard_metadata.packet_length").set(len);
    Field& f_instance_type = phv->get_field("standard_metadata.instance_type");
    f_instance_type.set(PKT_INSTANCE_TYPE_NORMAL);

    if (phv->has_field("intrinsic_metadata.ingress_global_timestamp")) {
        phv->get_field("intrinsic_metadata.ingress_global_timestamp")
            .set(get_ts().count());
    }

    input_buffer->push_front(
        InputBuffer::PacketType::NORMAL, std::move(packet));
    return 0;
}

void SimpleSwitch::start_and_return_()
{
    check_queueing_metadata();

    threads_.push_back(std::thread(&SimpleSwitch::ingress_thread, this));
    for (size_t i = 0; i < nb_egress_threads; i++) {
        threads_.push_back(std::thread(&SimpleSwitch::egress_thread, this, i));
    }
    threads_.push_back(std::thread(&SimpleSwitch::transmit_thread, this));
}

void SimpleSwitch::swap_notify_()
{
    bm::Logger::get()->debug(
        "simple_switch target has been notified of a config swap");
    check_queueing_metadata();
}

SimpleSwitch::~SimpleSwitch()
{
    input_buffer->push_front(
        InputBuffer::PacketType::SENTINEL, nullptr);
    for (size_t i = 0; i < nb_egress_threads; i++) {
        // The push_front call is called inside a while loop because there is no
        // guarantee that the sentinel was enqueued otherwise. It should not be an
        // issue because at this stage the ingress thread has been sent a signal to
        // stop, and only egress clones can be sent to the buffer.
        while (egress_buffers.push_front(i, 0, nullptr) == 0)
            continue;
    }
    output_buffer.push_front(nullptr);
    for (auto& thread_ : threads_) {
        thread_.join();
    }
}

void SimpleSwitch::reset_target_state_()
{
    bm::Logger::get()->debug("Resetting simple_switch target-specific state");
    get_component<McSimplePreLAG>()->reset_state();
}

bool SimpleSwitch::mirroring_add_session(mirror_id_t mirror_id,
    const MirroringSessionConfig& config)
{
    return mirroring_sessions->add_session(mirror_id, config);
}

bool SimpleSwitch::mirroring_delete_session(mirror_id_t mirror_id)
{
    return mirroring_sessions->delete_session(mirror_id);
}

bool SimpleSwitch::mirroring_get_session(mirror_id_t mirror_id,
    MirroringSessionConfig* config) const
{
    return mirroring_sessions->get_session(mirror_id, config);
}

int SimpleSwitch::set_egress_priority_queue_depth(size_t port, size_t priority,
    const size_t depth_pkts)
{
    egress_buffers.set_capacity(port, priority, depth_pkts);
    return 0;
}

int SimpleSwitch::set_egress_queue_depth(size_t port, const size_t depth_pkts)
{
    egress_buffers.set_capacity(port, depth_pkts);
    return 0;
}

int SimpleSwitch::set_all_egress_queue_depths(const size_t depth_pkts)
{
    egress_buffers.set_capacity_for_all(depth_pkts);
    return 0;
}

int SimpleSwitch::set_egress_priority_queue_rate(size_t port, size_t priority,
    const uint64_t rate_pps)
{
    egress_buffers.set_rate(port, priority, rate_pps);
    return 0;
}

int SimpleSwitch::set_egress_queue_rate(size_t port, const uint64_t rate_pps)
{
    egress_buffers.set_rate(port, rate_pps);
    return 0;
}

int SimpleSwitch::set_all_egress_queue_rates(const uint64_t rate_pps)
{
    egress_buffers.set_rate_for_all(rate_pps);
    return 0;
}

uint64_t
SimpleSwitch::get_time_elapsed_us() const
{
    return get_ts().count();
}

uint64_t
SimpleSwitch::get_time_since_epoch_us() const
{
    auto tp = clock::now();
    return duration_cast<ts_res>(tp.time_since_epoch()).count();
}

void SimpleSwitch::set_transmit_fn(TransmitFn fn)
{
    my_transmit_fn = std::move(fn);
}

void SimpleSwitch::transmit_thread()
{
    while (1) {
        std::unique_ptr<Packet> packet;
        output_buffer.pop_back(&packet);
        if (packet == nullptr)
            break;
        BMELOG(packet_out, *packet);
        BMLOG_DEBUG_PKT(*packet, "Transmitting packet of size {} out of port {}",
            packet->get_data_size(), packet->get_egress_port());
        my_transmit_fn(packet->get_egress_port(), packet->get_packet_id(),
            packet->data(), packet->get_data_size());
    }
}

ts_res
SimpleSwitch::get_ts() const
{
    return duration_cast<ts_res>(clock::now() - start); // rewrite? check out the point
}

void SimpleSwitch::enqueue(port_t egress_port, std::unique_ptr<Packet>&& packet)
{
    packet->set_egress_port(egress_port);

    PHV* phv = packet->get_phv();

    if (with_queueing_metadata) {
        phv->get_field("queueing_metadata.enq_timestamp").set(get_ts().count());
        phv->get_field("queueing_metadata.enq_qdepth")
            .set(egress_buffers.size(egress_port));
    }

    size_t priority = phv->has_field(SSWITCH_PRIORITY_QUEUEING_SRC) ? phv->get_field(SSWITCH_PRIORITY_QUEUEING_SRC).get<size_t>() : 0u;
    if (priority >= nb_queues_per_port) {
        bm::Logger::get()->error("Priority out of range, dropping packet");
        return;
    }
    egress_buffers.push_front(
        egress_port, nb_queues_per_port - 1 - priority,
        std::move(packet));
}

// used for ingress cloning, resubmit
void SimpleSwitch::copy_field_list_and_set_type(
    const std::unique_ptr<Packet>& packet,
    const std::unique_ptr<Packet>& packet_copy,
    PktInstanceType copy_type, p4object_id_t field_list_id)
{
    PHV* phv_copy = packet_copy->get_phv();
    phv_copy->reset_metadata();
    FieldList* field_list = this->get_field_list(field_list_id);
    field_list->copy_fields_between_phvs(phv_copy, packet->get_phv());
    phv_copy->get_field("standard_metadata.instance_type").set(copy_type);
}

void SimpleSwitch::check_queueing_metadata()
{
    // TODO(antonin): add qid in required fields
    bool enq_timestamp_e = field_exists("queueing_metadata", "enq_timestamp");
    bool enq_qdepth_e = field_exists("queueing_metadata", "enq_qdepth");
    bool deq_timedelta_e = field_exists("queueing_metadata", "deq_timedelta");
    bool deq_qdepth_e = field_exists("queueing_metadata", "deq_qdepth");
    if (enq_timestamp_e || enq_qdepth_e || deq_timedelta_e || deq_qdepth_e) {
        if (enq_timestamp_e && enq_qdepth_e && deq_timedelta_e && deq_qdepth_e) {
            with_queueing_metadata = true;
            return;
        } else {
            bm::Logger::get()->warn(
                "Your JSON input defines some but not all queueing metadata fields");
        }
    }
    with_queueing_metadata = false;
}

void SimpleSwitch::multicast(Packet* packet, unsigned int mgid)
{
    auto* phv = packet->get_phv();
    auto& f_rid = phv->get_field("intrinsic_metadata.egress_rid");
    const auto pre_out = pre->replicate({ mgid });
    auto packet_size = packet->get_register(RegisterAccess::PACKET_LENGTH_REG_IDX);
    for (const auto& out : pre_out) {
        auto egress_port = out.egress_port;
        BMLOG_DEBUG_PKT(*packet, "Replicating packet on port {}", egress_port);
        f_rid.set(out.rid);
        std::unique_ptr<Packet> packet_copy = packet->clone_with_phv_ptr();
        RegisterAccess::clear_all(packet_copy.get());
        packet_copy->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX,
            packet_size);
        enqueue(egress_port, std::move(packet_copy));
    }
}

void SimpleSwitch::ingress_thread()
{
    PHV* phv;

    while (1) {
        std::unique_ptr<Packet> packet;
        input_buffer->pop_back(&packet);
        if (packet == nullptr)
            break;

        // TODO(antonin): only update these if swapping actually happened?
        Parser* parser = this->get_parser("parser");
        Pipeline* ingress_mau = this->get_pipeline("ingress");

        phv = packet->get_phv();

        port_t ingress_port = packet->get_ingress_port();
        (void)ingress_port;
        BMLOG_DEBUG_PKT(*packet, "Processing packet received on port {}",
            ingress_port);

        auto ingress_packet_size = packet->get_register(RegisterAccess::PACKET_LENGTH_REG_IDX);

        /* This looks like it comes out of the blue. However this is needed for
           ingress cloning. The parser updates the buffer state (pops the parsed
           headers) to make the deparser's job easier (the same buffer is
           re-used). But for ingress cloning, the original packet is needed. This
           kind of looks hacky though. Maybe a better solution would be to have the
           parser leave the buffer unchanged, and move the pop logic to the
           deparser. TODO? */
        const Packet::buffer_state_t packet_in_state = packet->save_buffer_state();
        parser->parse(packet.get());

        if (phv->has_field("standard_metadata.parser_error")) {
            phv->get_field("standard_metadata.parser_error").set(packet->get_error_code().get());
        }

        if (phv->has_field("standard_metadata.checksum_error")) {
            phv->get_field("standard_metadata.checksum_error").set(packet->get_checksum_error() ? 1 : 0);
        }

        ingress_mau->apply(packet.get());

        packet->reset_exit();

        Field& f_egress_spec = phv->get_field("standard_metadata.egress_spec");
        port_t egress_spec = f_egress_spec.get_uint();

        auto clone_mirror_session_id = RegisterAccess::get_clone_mirror_session_id(packet.get());
        auto clone_field_list = RegisterAccess::get_clone_field_list(packet.get());

        int learn_id = RegisterAccess::get_lf_field_list(packet.get());
        unsigned int mgid = 0u;

        // detect mcast support, if this is true we assume that other fields needed
        // for mcast are also defined
        if (phv->has_field("intrinsic_metadata.mcast_grp")) {
            Field& f_mgid = phv->get_field("intrinsic_metadata.mcast_grp");
            mgid = f_mgid.get_uint();
        }

        // INGRESS CLONING
        if (clone_mirror_session_id) {
            BMLOG_DEBUG_PKT(*packet, "Cloning packet at ingress");
            RegisterAccess::set_clone_mirror_session_id(packet.get(), 0);
            RegisterAccess::set_clone_field_list(packet.get(), 0);
            MirroringSessionConfig config;
            // Extract the part of clone_mirror_session_id that contains the
            // actual session id.
            clone_mirror_session_id &= RegisterAccess::MIRROR_SESSION_ID_MASK;
            bool is_session_configured = mirroring_get_session(
                static_cast<mirror_id_t>(clone_mirror_session_id), &config);
            if (is_session_configured) {
                const Packet::buffer_state_t packet_out_state = packet->save_buffer_state();
                packet->restore_buffer_state(packet_in_state);
                p4object_id_t field_list_id = clone_field_list;
                std::unique_ptr<Packet> packet_copy = packet->clone_no_phv_ptr();
                RegisterAccess::clear_all(packet_copy.get());
                packet_copy->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX,
                    ingress_packet_size);
                // we need to parse again
                // the alternative would be to pay the (huge) price of PHV copy for
                // every ingress packet
                parser->parse(packet_copy.get());
                copy_field_list_and_set_type(packet, packet_copy,
                    PKT_INSTANCE_TYPE_INGRESS_CLONE,
                    field_list_id);
                if (config.mgid_valid) {
                    BMLOG_DEBUG_PKT(*packet, "Cloning packet to MGID {}", config.mgid);
                    multicast(packet_copy.get(), config.mgid);
                }
                if (config.egress_port_valid) {
                    BMLOG_DEBUG_PKT(*packet, "Cloning packet to egress port {}",
                        config.egress_port);
                    enqueue(config.egress_port, std::move(packet_copy));
                }
                packet->restore_buffer_state(packet_out_state);
            }
        }

        // LEARNING
        if (learn_id > 0) {
            get_learn_engine()->learn(learn_id, *packet.get());
        }

        // RESUBMIT
        auto resubmit_flag = RegisterAccess::get_resubmit_flag(packet.get());
        if (resubmit_flag) {
            BMLOG_DEBUG_PKT(*packet, "Resubmitting packet");
            // get the packet ready for being parsed again at the beginning of
            // ingress
            packet->restore_buffer_state(packet_in_state);
            p4object_id_t field_list_id = resubmit_flag;
            RegisterAccess::set_resubmit_flag(packet.get(), 0);
            // TODO(antonin): a copy is not needed here, but I don't yet have an
            // optimized way of doing this
            std::unique_ptr<Packet> packet_copy = packet->clone_no_phv_ptr();
            PHV* phv_copy = packet_copy->get_phv();
            copy_field_list_and_set_type(packet, packet_copy,
                PKT_INSTANCE_TYPE_RESUBMIT,
                field_list_id);
            RegisterAccess::clear_all(packet_copy.get());
            packet_copy->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX,
                ingress_packet_size);
            phv_copy->get_field("standard_metadata.packet_length")
                .set(ingress_packet_size);
            input_buffer->push_front(
                InputBuffer::PacketType::RESUBMIT, std::move(packet_copy));
            continue;
        }

        // MULTICAST
        if (mgid != 0) {
            BMLOG_DEBUG_PKT(*packet, "Multicast requested for packet");
            auto& f_instance_type = phv->get_field("standard_metadata.instance_type");
            f_instance_type.set(PKT_INSTANCE_TYPE_REPLICATION);
            multicast(packet.get(), mgid);
            // when doing multicast, we discard the original packet
            continue;
        }

        port_t egress_port = egress_spec;
        BMLOG_DEBUG_PKT(*packet, "Egress port is {}", egress_port);

        if (egress_port == drop_port) { // drop packet
            BMLOG_DEBUG_PKT(*packet, "Dropping packet at the end of ingress");
            continue;
        }
        auto& f_instance_type = phv->get_field("standard_metadata.instance_type");
        f_instance_type.set(PKT_INSTANCE_TYPE_NORMAL);

        enqueue(egress_port, std::move(packet));
    }
}

void SimpleSwitch::egress_thread(size_t worker_id)
{
    PHV* phv;

    while (1) {
        std::unique_ptr<Packet> packet;
        size_t port;
        size_t priority;
        egress_buffers.pop_back(worker_id, &port, &priority, &packet);
        if (packet == nullptr)
            break;

        Deparser* deparser = this->get_deparser("deparser");
        Pipeline* egress_mau = this->get_pipeline("egress");

        phv = packet->get_phv();

        if (phv->has_field("intrinsic_metadata.egress_global_timestamp")) {
            phv->get_field("intrinsic_metadata.egress_global_timestamp")
                .set(get_ts().count());
        }

        if (with_queueing_metadata) {
            auto enq_timestamp = phv->get_field("queueing_metadata.enq_timestamp").get<ts_res::rep>();
            phv->get_field("queueing_metadata.deq_timedelta").set(get_ts().count() - enq_timestamp);
            phv->get_field("queueing_metadata.deq_qdepth").set(egress_buffers.size(port));
            if (phv->has_field("queueing_metadata.qid")) {
                auto& qid_f = phv->get_field("queueing_metadata.qid");
                qid_f.set(nb_queues_per_port - 1 - priority);
            }
        }

        phv->get_field("standard_metadata.egress_port").set(port);

        Field& f_egress_spec = phv->get_field("standard_metadata.egress_spec");
        f_egress_spec.set(0);

        phv->get_field("standard_metadata.packet_length").set(packet->get_register(RegisterAccess::PACKET_LENGTH_REG_IDX));

        egress_mau->apply(packet.get());

        auto clone_mirror_session_id = RegisterAccess::get_clone_mirror_session_id(packet.get());
        auto clone_field_list = RegisterAccess::get_clone_field_list(packet.get());

        // EGRESS CLONING
        if (clone_mirror_session_id) {
            BMLOG_DEBUG_PKT(*packet, "Cloning packet at egress");
            RegisterAccess::set_clone_mirror_session_id(packet.get(), 0);
            RegisterAccess::set_clone_field_list(packet.get(), 0);
            MirroringSessionConfig config;
            // Extract the part of clone_mirror_session_id that contains the
            // actual session id.
            clone_mirror_session_id &= RegisterAccess::MIRROR_SESSION_ID_MASK;
            bool is_session_configured = mirroring_get_session(
                static_cast<mirror_id_t>(clone_mirror_session_id), &config);
            if (is_session_configured) {
                p4object_id_t field_list_id = clone_field_list;
                std::unique_ptr<Packet> packet_copy = packet->clone_with_phv_reset_metadata_ptr();
                PHV* phv_copy = packet_copy->get_phv();
                FieldList* field_list = this->get_field_list(field_list_id);
                field_list->copy_fields_between_phvs(phv_copy, phv);
                phv_copy->get_field("standard_metadata.instance_type")
                    .set(PKT_INSTANCE_TYPE_EGRESS_CLONE);
                auto packet_size = packet->get_register(RegisterAccess::PACKET_LENGTH_REG_IDX);
                RegisterAccess::clear_all(packet_copy.get());
                packet_copy->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX,
                    packet_size);
                if (config.mgid_valid) {
                    BMLOG_DEBUG_PKT(*packet, "Cloning packet to MGID {}", config.mgid);
                    multicast(packet_copy.get(), config.mgid);
                }
                if (config.egress_port_valid) {
                    BMLOG_DEBUG_PKT(*packet, "Cloning packet to egress port {}",
                        config.egress_port);
                    enqueue(config.egress_port, std::move(packet_copy));
                }
            }
        }

        // TODO(antonin): should not be done like this in egress pipeline
        port_t egress_spec = f_egress_spec.get_uint();
        if (egress_spec == drop_port) { // drop packet
            BMLOG_DEBUG_PKT(*packet, "Dropping packet at the end of egress");
            continue;
        }

        deparser->deparse(packet.get());

        // RECIRCULATE
        auto recirculate_flag = RegisterAccess::get_recirculate_flag(packet.get());
        if (recirculate_flag) {
            BMLOG_DEBUG_PKT(*packet, "Recirculating packet");
            p4object_id_t field_list_id = recirculate_flag;
            RegisterAccess::set_recirculate_flag(packet.get(), 0);
            FieldList* field_list = this->get_field_list(field_list_id);
            // TODO(antonin): just like for resubmit, there is no need for a copy
            // here, but it is more convenient for this first prototype
            std::unique_ptr<Packet> packet_copy = packet->clone_no_phv_ptr();
            PHV* phv_copy = packet_copy->get_phv();
            phv_copy->reset_metadata();
            field_list->copy_fields_between_phvs(phv_copy, phv);
            phv_copy->get_field("standard_metadata.instance_type")
                .set(PKT_INSTANCE_TYPE_RECIRC);
            size_t packet_size = packet_copy->get_data_size();
            RegisterAccess::clear_all(packet_copy.get());
            packet_copy->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX,
                packet_size);
            phv_copy->get_field("standard_metadata.packet_length").set(packet_size);
            // TODO(antonin): really it may be better to create a new packet here or
            // to fold this functionality into the Packet class?
            packet_copy->set_ingress_length(packet_size);
            input_buffer->push_front(
                InputBuffer::PacketType::RECIRCULATE, std::move(packet_copy));
            continue;
        }

        output_buffer.push_front(std::move(packet));
    }
}
