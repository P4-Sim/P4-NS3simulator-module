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
 * Author: PengKuang <kphf1995cm@outlook.com>
 * Modified: MaMingyu <myma979@gmail.com>
 *
 * @todo Currently the NS LOG system cannot be used.
 */

#include "ns3/p4-model.h"
#include "ns3/arp-l3-protocol.h"
#include "ns3/delay-jitter-estimation.h"
#include "ns3/ethernet-header.h"
#include "ns3/global.h"
#include "ns3/helper.h"
#include "ns3/log.h"
#include "ns3/node.h"
#include "ns3/simulator.h"
// new added
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
// bis here
#include <bm/SimpleSwitch.h>
#include <bm/bm_runtime/bm_runtime.h>
#include <bm/bm_sim/core/primitives.h>
#include <bm/bm_sim/options_parse.h>
#include <bm/bm_sim/simple_pre.h>
#include <bm/bm_sim/switch.h>
#include <bm/simple_switch/runner.h>

using namespace ns3;
using bm::Switch;

NS_OBJECT_ENSURE_REGISTERED(P4Model);
// NS_LOG_COMPONENT_DEFINE(P4Model);

// take out the handler from simple_switch
namespace sswitch_runtime {
shared_ptr<SimpleSwitchIf> get_handler(SimpleSwitch* sw);
} // namespace sswitch_runtime

namespace {

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

extern int import_primitives();
packet_id_t P4Model::packet_id = 0;

TypeId P4Model::GetTypeId(void)
{
    static TypeId tid = TypeId("ns3::P4Model")
                            .SetParent<Object>()
                            .SetGroupName("Network")
                            .AddTraceSource("DropNum1Queue",
                                "The packets drop number in 1st queue",
                                MakeTraceSourceAccessor(&P4Model::m_qDropNum_1),
                                "ns3::TracedValueCallback::Int64")
                            .AddTraceSource("DropNum2Queue",
                                "The packets drop number in 2st queue",
                                MakeTraceSourceAccessor(&P4Model::m_qDropNum_2),
                                "ns3::TracedValueCallback::Int64")
                            .AddTraceSource("DropNum3Queue",
                                "The packets drop number in 3st queue",
                                MakeTraceSourceAccessor(&P4Model::m_qDropNum_3),
                                "ns3::TracedValueCallback::Int64");
    return tid;
}

class P4Model::MirroringSessions {
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
class P4Model::InputBuffer {
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

    int push_front(PacketType packet_type, std::unique_ptr<bm::Packet>&& item)
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

    void pop_back(std::unique_ptr<bm::Packet>* pItem)
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
    using QueueImpl = std::deque<std::unique_ptr<bm::Packet>>;

    int push_front(QueueImpl* queue, size_t capacity,
        std::condition_variable* cvar,
        std::unique_ptr<bm::Packet>&& item, bool blocking)
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

/*
P4Model::P4Model(P4NetDevice* netDevice) :
        m_pre(new bm::McSimplePre()) {
        //! A simple, 2-level, packet replication engine, configurable by the control
        //! plane. See replicate() for more information.
        m_pNetDevice = netDevice;

        add_component<bm::McSimplePre>(m_pre);

        m_argParser = new bm::TargetParserBasic();
        add_required_field("standard_metadata", "ingress_port");	// sm14, v1m
        add_required_field("standard_metadata", "packet_length");	// sm14, v1m
        add_required_field("standard_metadata", "instance_type");	// sm14, v1m
        add_required_field("standard_metadata", "egress_spec");		// sm14, v1m
        add_required_field("standard_metadata", "egress_port");		// sm14, v1m
        //add_required_field("standard_metadata", "egress_instance"); // sm14
        //add_required_field("standard_metadata", "checksum_error"); 	// v1m

    force_arith_header("standard_metadata");
    force_arith_header("queueing_metadata");
    force_arith_header("intrinsic_metadata");

        import_primitives();
}*/

P4Model::P4Model(P4NetDevice* netDevice, bool enable_swap,
    port_t drop_port, size_t nb_queues_per_port)
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
    m_pNetDevice = netDevice;

    add_component<McSimplePreLAG>(pre);

    add_required_field("standard_metadata", "ingress_port");
    add_required_field("standard_metadata", "packet_length");
    add_required_field("standard_metadata", "instance_type");
    add_required_field("standard_metadata", "egress_spec");
    add_required_field("standard_metadata", "egress_port");

    force_arith_header("standard_metadata");
    force_arith_header("queueing_metadata");
    force_arith_header("intrinsic_metadata");

    import_primitives();

    // ns3 settings init @mingyu
    address_num = 0; 
}

int P4Model::init(int argc, char* argv[])
{

    // NS_LOG_FUNCTION(this);

    int status = 0;
    // use local call to populate flowtable
    if (P4GlobalVar::g_populateFlowTableWay == LOCAL_CALL) {
        // This mode can only deal with "exact" matching table, the "lpm" matching
        // by now can not use. @todo -mingyu
        status = this->InitFromCommandLineOptionsLocal(argc, argv, m_argParser);
    } else if (P4GlobalVar::g_populateFlowTableWay == RUNTIME_CLI) {

        // start thrift server , use runtime_CLI populate flowtable
        std::cout << "P4GlobalVar::g_populateFlowTableWay == RUNTIME_CLI" << std::endl;

        /*
        // This method is from src
        // This will connect to the simple_switch thrift server and input the command.
        // by now the bm::switch and the bm::simple_switch is not the same thing, so
        // the "sswitch_runtime::get_handler()" by now can not use. @todo -mingyu

        status = this->init_from_command_line_options(argc, argv, m_argParser);
        int thriftPort = this->get_runtime_port();
        std::cout << "thrift port : " << thriftPort << std::endl;
        bm_runtime::start_server(this, thriftPort);
        //NS_LOG_LOGIC("Wait " << P4GlobalVar::g_runtimeCliTime << " seconds for RuntimeCLI operations ");
        std::this_thread::sleep_for(std::chrono::seconds(P4GlobalVar::g_runtimeCliTime));
        //@todo BUG: THIS MAY CHANGED THE API
        using ::sswitch_runtime::SimpleSwitchIf;
        using ::sswitch_runtime::SimpleSwitchProcessor;
        bm_runtime::add_service<SimpleSwitchIf, SimpleSwitchProcessor>(
                "simple_switch", sswitch_runtime::get_handler(this));
        */
    } else if (P4GlobalVar::g_populateFlowTableWay == NS3PIFOTM) {

        // This method for setting the json file and populate the flow table taken from "ns3-PIFO-TM"

        static int thriftPort = 9090; // the thrift port will from 9090 increase with 1.

        //! ===== The first part: init the sw with json.
        bm::OptionsParser opt_parser;
        opt_parser.config_file_path = P4GlobalVar::g_p4JsonPath;
        opt_parser.debugger_addr = std::string("ipc:///tmp/bmv2-") + std::to_string(thriftPort) + std::string("-debug.ipc");
        opt_parser.notifications_addr = std::string("ipc:///tmp/bmv2-") + std::to_string(thriftPort) + std::string("-notifications.ipc");
        opt_parser.file_logger = std::string("/tmp/bmv2-") + std::to_string(thriftPort) + std::string("-pipeline.log");
        opt_parser.thrift_port = thriftPort++;
        opt_parser.console_logging = true;

        //! Initialize the switch using an bm::OptionsParser instance.
        int status = this->init_from_options_parser(opt_parser);
        if (status != 0) {
            std::exit(status);
        }

        // ！======The second part: init the sw flow table settings.
        int port = get_runtime_port();
        bm_runtime::start_server(this, port);
        std::this_thread::sleep_for(std::chrono::seconds(P4GlobalVar::g_runtimeCliTime));

        // Run the CLI commands to populate table entries
        std::string cmd = "python /home/p4/p4simulator/src/bmv2-tools/run_bmv2_CLI --thrift_port "
            + std::to_string(port) + " " + P4GlobalVar::g_flowTablePath;
        std::system(cmd.c_str());
        // bm_runtime::stop_server(); // 关闭bm_runtime服务
    } else {
        return -1;
    }
    if (status != 0) {
        // NS_LOG_LOGIC("ERROR: the P4 Model switch init failed in P4Model::init.");
        std::exit(status);
        return -1;
    }
    return 0;
}

int P4Model::InitFromCommandLineOptionsLocal(int argc, char* argv[], bm::TargetParserBasic* tp)
{
    // NS_LOG_FUNCTION(this);
    bm::OptionsParser parser;
    parser.parse(argc, argv, tp);
    // NS_LOG_LOGIC("parse pass");
    std::shared_ptr<bm::TransportIface> transport = nullptr;
    int status = 0;
    if (transport == nullptr) {
#ifdef BMNANOMSG_ON
        // notifications_addr = parser.notifications_addr;
        transport = std::shared_ptr<bm::TransportIface>(
            TransportIface::make_nanomsg(parser.notifications_addr));
#else
        // notifications_addr = "";
        transport = std::shared_ptr<bm::TransportIface>(bm::TransportIface::make_dummy());
#endif
    }
    if (parser.no_p4)
        // with out p4-json, acctually the switch will wait for the configuration(p4-json) before work
        status = init_objects_empty(parser.device_id, transport);
    else
        // load p4-json to switch
        status = init_objects(parser.config_file_path, parser.device_id, transport);
    return status;
}

/**
 * @brief process receive pkts as bmv2
 */
int P4Model::receive_(port_t port_num, const char* buffer, int len)
{
    // we limit the packet buffer to original size + 512 bytes, which means we
    // cannot add more than 512 bytes of header data to the packet, which should
    // be more than enough
    auto packet = new_packet_ptr(port_num, packet_id++, len,
        bm::PacketBuffer(len + 512, buffer, len));

#ifdef BMNANOMSG_ON
    BMELOG(packet_in, *packet);
#endif
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

/*Multithread support*/
void P4Model::start_and_return_()
{
    check_queueing_metadata();

    threads_.push_back(std::thread(&P4Model::ingress_thread, this));
    for (size_t i = 0; i < nb_egress_threads; i++) {
        threads_.push_back(std::thread(&P4Model::egress_thread, this, i));
    }
    threads_.push_back(std::thread(&P4Model::transmit_thread, this)); // make this part with main thread
}

void P4Model::swap_notify_()
{
    bm::Logger::get()->debug(
        "simple_switch target has been notified of a config swap");
    check_queueing_metadata();
}

P4Model::~P4Model()
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

void P4Model::reset_target_state_()
{
    bm::Logger::get()->debug("Resetting simple_switch target-specific state");
    get_component<McSimplePreLAG>()->reset_state();
}

bool P4Model::mirroring_add_session(mirror_id_t mirror_id,
    const MirroringSessionConfig& config)
{
    return mirroring_sessions->add_session(mirror_id, config);
}

bool P4Model::mirroring_delete_session(mirror_id_t mirror_id)
{
    return mirroring_sessions->delete_session(mirror_id);
}

bool P4Model::mirroring_get_session(mirror_id_t mirror_id,
    MirroringSessionConfig* config) const
{
    return mirroring_sessions->get_session(mirror_id, config);
}

int P4Model::set_egress_priority_queue_depth(size_t port, size_t priority,
    const size_t depth_pkts)
{
    egress_buffers.set_capacity(port, priority, depth_pkts);
    return 0;
}

int P4Model::set_egress_queue_depth(size_t port, const size_t depth_pkts)
{
    egress_buffers.set_capacity(port, depth_pkts);
    return 0;
}

int P4Model::set_all_egress_queue_depths(const size_t depth_pkts)
{
    egress_buffers.set_capacity_for_all(depth_pkts);
    return 0;
}

int P4Model::set_egress_priority_queue_rate(size_t port, size_t priority,
    const uint64_t rate_pps)
{
    egress_buffers.set_rate(port, priority, rate_pps);
    return 0;
}

int P4Model::set_egress_queue_rate(size_t port, const uint64_t rate_pps)
{
    egress_buffers.set_rate(port, rate_pps);
    return 0;
}

int P4Model::set_all_egress_queue_rates(const uint64_t rate_pps)
{
    egress_buffers.set_rate_for_all(rate_pps);
    return 0;
}

uint64_t
P4Model::get_time_elapsed_us() const
{
    return get_ts().count();
}

uint64_t
P4Model::get_time_since_epoch_us() const
{
    auto tp = clock::now();
    return duration_cast<ts_res>(tp.time_since_epoch()).count();
}

void P4Model::set_transmit_fn(TransmitFn fn)
{
    my_transmit_fn = std::move(fn);
}

void P4Model::transmit_thread()
{   
    // bmv2 packet
    while (1) {
        std::unique_ptr<bm::Packet> packet;
        output_buffer.pop_back(&packet);
        if (packet == nullptr)
            break;
#ifdef BMNANOMSG_ON
        BMELOG(packet_out, *packet);
        BMLOG_DEBUG_PKT(*packet, "Transmitting packet of size {} out of port {}",
            packet->get_data_size(), packet->get_egress_port());
#endif  
        // default transmit function
        /*my_transmit_fn(packet->get_egress_port(), packet->get_packet_id(),
            packet->data(), packet->get_data_size());*/
    
        // get the protocol and desination Address for ns-3 @mingyu
        
        m_mutex.lock();
        bm_queue.push(std::move(packet));
        m_mutex.unlock();

        /*
        PHV* phv = packet->get_phv();

        uint16_t protocol;
        if (phv->has_field("scalars.userMetadata._ns3i_protocol3")) {
            protocol = phv->get_field("scalars.userMetadata._ns3i_protocol3").get_int();
        }
        int des_idx = 0;
        if (phv->has_field("scalars.userMetadata._ns3i_destination4")) {
            des_idx = phv->get_field("scalars.userMetadata._ns3i_destination4").get_int();    
        }
        int port = 0;
        // take the port info into p4
        if (phv->has_field("standard_metadata.egress_spec")) {
            port = phv->get_field("standard_metadata.egress_spec").get_int();
        }
        if (phv->has_field("standard_metadata.egress_port")) {
            port = phv->get_field("standard_metadata.egress_port").get_int();
        }
        std::cout << "@mingyu after bmv2 port: " << port << " protocol " << protocol << " idx " << des_idx << std::endl;
        */
        // phv->get_field("standard_metadata.egress_port")
        
        
        /*
        if (phv->has_field("scalars.userMetadata._ns3i_protocol20")) {
            Field &f_mgid = phv->get_field("scalars.userMetadata._ns3i_protocol20");
            protocol = f_mgid.get_uint();
        } else if (phv->has_field("scalars.userMetadata._ns3i_protocol16")) {
            Field &f_mgid = phv->get_field("scalars.userMetadata._ns3i_protocol16");
            protocol = f_mgid.get_uint();
        } else {
            // warning
            std::cout << "No protocol for sending ns-3 packet!" << std::endl;
            protocol = 0;
        }

        int des_idx = 0;
        if (phv->has_field("scalars.userMetadata._ns3i_destination21")) {
            des_idx = phv->get_field("scalars.userMetadata._ns3i_destination21").get_uint();
        } else if (phv->has_field("scalars.userMetadata._ns3i_destination17")) {
            des_idx = phv->get_field("scalars.userMetadata._ns3i_destination17").get_uint();
        } else {
            // warning
            std::cout << "No destnation for sending ns-3 packet!" << std::endl;
            des_idx = 0;
        }
        
        int port = 0;
        // take the port info into p4
        if (phv->has_field("scalars.userMetadata._ns3i_port22")) {
            port = phv->get_field("scalars.userMetadata._ns3i_port22").get_uint();
        } else if (phv->has_field("scalars.userMetadata._ns3i_port18")) {
            port = phv->get_field("scalars.userMetadata._ns3i_port18").get_uint();
        } else {
            // warning
            std::cout << "No port info for sending ns-3 packet!" << std::endl;
        }
        */

        /*
        m_mutex.lock();
        bmpack pack_item = {std::move(packet), port, protocol, des_idx};
        bm_queue.push(pack_item);
        m_mutex.unlock();
        */


        /*// tranfer bmv2::packet to ns3::packet @mingyu
        void *bm2Buffer = packet.get()->data();
        size_t bm2Length = packet.get()->get_data_size();
        ns3::Packet ns3Packet((uint8_t*)(bm2Buffer), bm2Length);
        //Ptr<ns3::Packet> packetOut(&ns3Packet);
        
        // push into queue
        m_mutex.lock();
        ns3pack pack_item = {ns3Packet, port, protocol, des_idx};
        results_queue.push(pack_item);
        m_mutex.unlock();*/
        // CALL THE MAIN THREAD OF NS3 @mingyu
        //Time delay = NanoSeconds (1);  // 1 ns
        //Simulator::ScheduleWithContext (1, delay, &ns3::P4Model::TranferNSPakcets, ns3Packet, port, protocol, des_idx);
        // ERROR: incomplete type ‘ns3::EventMemberImplObjTraits<ns3::Packet>’ used in nested name specifier
        
        // Simulator::ScheduleNow (&ns3::P4Model::TranferNSPakcets, ns3Packet, port, protocol, des_idx);
    }
}

/*void P4Model::TranferNSPakcets(ns3::Packet packet, int port, 
    uint16_t protocol, int index)
{
    m_pNetDevice->SendNs3Packet(packet, port, protocol, destination_list[index]);
    std::cout << "success bmv2 -> ns3 recover." << std::endl;
}*/

ts_res P4Model::get_ts() const
{
    return duration_cast<ts_res>(clock::now() - start); // rewrite? check out the point
}

void P4Model::enqueue(port_t egress_port, std::unique_ptr<bm::Packet>&& packet)
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
void P4Model::copy_field_list_and_set_type(
    const std::unique_ptr<bm::Packet>& packet,
    const std::unique_ptr<bm::Packet>& packet_copy,
    PktInstanceType copy_type, p4object_id_t field_list_id)
{
    PHV* phv_copy = packet_copy->get_phv();
    phv_copy->reset_metadata();
    FieldList* field_list = this->get_field_list(field_list_id);
    field_list->copy_fields_between_phvs(phv_copy, packet->get_phv());
    phv_copy->get_field("standard_metadata.instance_type").set(copy_type);
}

void P4Model::check_queueing_metadata()
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

void P4Model::multicast(bm::Packet* packet, unsigned int mgid)
{
    auto* phv = packet->get_phv();
    auto& f_rid = phv->get_field("intrinsic_metadata.egress_rid");
    const auto pre_out = pre->replicate({ mgid });
    auto packet_size = packet->get_register(RegisterAccess::PACKET_LENGTH_REG_IDX);
    for (const auto& out : pre_out) {
        auto egress_port = out.egress_port;
#ifdef BMNANOMSG_ON
        BMLOG_DEBUG_PKT(*packet, "Replicating packet on port {}", egress_port);
#endif
        f_rid.set(out.rid);
        std::unique_ptr<bm::Packet> packet_copy = packet->clone_with_phv_ptr();
        RegisterAccess::clear_all(packet_copy.get());
        packet_copy->set_register(RegisterAccess::PACKET_LENGTH_REG_IDX,
            packet_size);
        enqueue(egress_port, std::move(packet_copy));
    }
}

void P4Model::ingress_thread()
{
    PHV* phv;

    while (1) {
        std::unique_ptr<bm::Packet> packet;
        input_buffer->pop_back(&packet);
        if (packet == nullptr)
            break;

        // TODO(antonin): only update these if swapping actually happened?
        Parser* parser = this->get_parser("parser");
        Pipeline* ingress_mau = this->get_pipeline("ingress");

        phv = packet->get_phv();

        port_t ingress_port = packet->get_ingress_port();
        (void)ingress_port;

#ifdef BMNANOMSG_ON
        BMLOG_DEBUG_PKT(*packet, "Processing packet received on port {}",
            ingress_port);
#endif

        auto ingress_packet_size = packet->get_register(RegisterAccess::PACKET_LENGTH_REG_IDX);

        /* This looks like it comes out of the blue. However this is needed for
           ingress cloning. The parser updates the buffer state (pops the parsed
           headers) to make the deparser's job easier (the same buffer is
           re-used). But for ingress cloning, the original packet is needed. This
           kind of looks hacky though. Maybe a better solution would be to have the
           parser leave the buffer unchanged, and move the pop logic to the
           deparser. TODO? */
        const bm::Packet::buffer_state_t packet_in_state = packet->save_buffer_state();
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
#ifdef BMNANOMSG_ON
            BMLOG_DEBUG_PKT(*packet, "Cloning packet at ingress");
#endif
            RegisterAccess::set_clone_mirror_session_id(packet.get(), 0);
            RegisterAccess::set_clone_field_list(packet.get(), 0);
            MirroringSessionConfig config;
            // Extract the part of clone_mirror_session_id that contains the
            // actual session id.
            clone_mirror_session_id &= RegisterAccess::MIRROR_SESSION_ID_MASK;
            bool is_session_configured = mirroring_get_session(
                static_cast<mirror_id_t>(clone_mirror_session_id), &config);
            if (is_session_configured) {
                const bm::Packet::buffer_state_t packet_out_state = packet->save_buffer_state();
                packet->restore_buffer_state(packet_in_state);
                p4object_id_t field_list_id = clone_field_list;
                std::unique_ptr<bm::Packet> packet_copy = packet->clone_no_phv_ptr();
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
#ifdef BMNANOMSG_ON
                    BMLOG_DEBUG_PKT(*packet, "Cloning packet to MGID {}", config.mgid);
#endif
                    multicast(packet_copy.get(), config.mgid);
                }
                if (config.egress_port_valid) {
#ifdef BMNANOMSG_ON
                    BMLOG_DEBUG_PKT(*packet, "Cloning packet to egress port {}",
                        config.egress_port);
#endif
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
#ifdef BMNANOMSG_ON
            BMLOG_DEBUG_PKT(*packet, "Resubmitting packet");
#endif
            // get the packet ready for being parsed again at the beginning of
            // ingress
            packet->restore_buffer_state(packet_in_state);
            p4object_id_t field_list_id = resubmit_flag;
            RegisterAccess::set_resubmit_flag(packet.get(), 0);
            // TODO(antonin): a copy is not needed here, but I don't yet have an
            // optimized way of doing this
            std::unique_ptr<bm::Packet> packet_copy = packet->clone_no_phv_ptr();
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
#ifdef BMNANOMSG_ON
            BMLOG_DEBUG_PKT(*packet, "Multicast requested for packet");
#endif
            auto& f_instance_type = phv->get_field("standard_metadata.instance_type");
            f_instance_type.set(PKT_INSTANCE_TYPE_REPLICATION);
            multicast(packet.get(), mgid);
            // when doing multicast, we discard the original packet
            continue;
        }

        port_t egress_port = egress_spec;
#ifdef BMNANOMSG_ON
        BMLOG_DEBUG_PKT(*packet, "Egress port is {}", egress_port);
#endif
        if (egress_port == drop_port) { // drop packet
#ifdef BMNANOMSG_ON
            BMLOG_DEBUG_PKT(*packet, "Dropping packet at the end of ingress");
#endif
            continue;
        }
        auto& f_instance_type = phv->get_field("standard_metadata.instance_type");
        f_instance_type.set(PKT_INSTANCE_TYPE_NORMAL);

        enqueue(egress_port, std::move(packet));
    }
}

void P4Model::egress_thread(size_t worker_id)
{
    PHV* phv;

    while (1) {
        std::unique_ptr<bm::Packet> packet;
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
#ifdef BMNANOMSG_ON
            BMLOG_DEBUG_PKT(*packet, "Cloning packet at egress");
#endif
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
                std::unique_ptr<bm::Packet> packet_copy = packet->clone_with_phv_reset_metadata_ptr();
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
#ifdef BMNANOMSG_ON
                    BMLOG_DEBUG_PKT(*packet, "Cloning packet to MGID {}", config.mgid);
#endif
                    multicast(packet_copy.get(), config.mgid);
                }
                if (config.egress_port_valid) {
#ifdef BMNANOMSG_ON
                    BMLOG_DEBUG_PKT(*packet, "Cloning packet to egress port {}",
                        config.egress_port);
#endif
                    enqueue(config.egress_port, std::move(packet_copy));
                }
            }
        }

        // TODO(antonin): should not be done like this in egress pipeline
        port_t egress_spec = f_egress_spec.get_uint();
        if (egress_spec == drop_port) { // drop packet
#ifdef BMNANOMSG_ON
            BMLOG_DEBUG_PKT(*packet, "Dropping packet at the end of egress");
#endif
            continue;
        }

        deparser->deparse(packet.get());

        // RECIRCULATE
        auto recirculate_flag = RegisterAccess::get_recirculate_flag(packet.get());
        if (recirculate_flag) {
#ifdef BMNANOMSG_ON
            BMLOG_DEBUG_PKT(*packet, "Recirculating packet");
#endif
            p4object_id_t field_list_id = recirculate_flag;
            RegisterAccess::set_recirculate_flag(packet.get(), 0);
            FieldList* field_list = this->get_field_list(field_list_id);
            // TODO(antonin): just like for resubmit, there is no need for a copy
            // here, but it is more convenient for this first prototype
            std::unique_ptr<bm::Packet> packet_copy = packet->clone_no_phv_ptr();
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

int P4Model::ReceivePacket(Ptr<ns3::Packet> packetIn, int inPort,
    uint16_t protocol, Address const& destination)
{
    // **************Change ns3::Packet to bm::Packet***************************
    int ns3Length = packetIn->GetSize();
    uint8_t* ns3Buffer = new uint8_t[ns3Length];
    packetIn->CopyData(ns3Buffer, ns3Length);

    // we limit the packet buffer to original size + 512 bytes, which means we
    // cannot add more than 512 bytes of header data to the packet, which should
    // be more than enough
    std::unique_ptr<bm::Packet> packet = new_packet_ptr(inPort, m_pktID++,
        ns3Length, bm::PacketBuffer(ns3Length + 512, (char*)ns3Buffer, ns3Length));
    delete[] ns3Buffer;

#ifdef BMNANOMSG_ON
    BMELOG(packet_in, *packet);
#endif
    if (packet) {
        PHV* phv = packet->get_phv();
        int len = packet.get()->get_data_size();
        packet.get()->set_ingress_port(inPort);

        // many current P4 programs assume this
        // it is also part of the original P4 spec
        phv->reset_metadata();
        RegisterAccess::clear_all(packet.get());

        // setting standard metadata
        phv->get_field("standard_metadata.ingress_port").set(inPort);
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

        /* Record the ns3::protocol, ns3::destinatio into bm::packet, this is
        useful, because after the 3 buffers and Ingress Egress loops, or resubmit/
        recirculaiton etc, maybe bm::packet will get a different order. So I think
        this situation can only be solved by adding additional information to
        the bm::package. @mingyu
        codel1:	_ns3i_protocol20; _ns3i_destination21
        codel2: _ns3i_protocol16; _ns3i_destination17
        */
        
        // test version
        if (phv->has_field("scalars.userMetadata._ns3i_protocol3")) {
            phv->get_field("scalars.userMetadata._ns3i_protocol3").set(protocol);
        }
        
        int index_dest_address = 0;
        if (std::find(destination_list.begin(), destination_list.end(), destination) == destination_list.end()){
            destination_list.push_back(destination);
            index_dest_address = destination_list.size() - 1;
        }
        else{
            auto it = std::find(destination_list.begin(), destination_list.end(), destination);
            index_dest_address = std::distance(destination_list.begin(), it);
        }
        // std::cout << "index of destadd: " << index_dest_address << " total list size: " << destination_list.size() << std::endl;
        
        if (phv->has_field("scalars.userMetadata._ns3i_destination4")) {
            phv->get_field("scalars.userMetadata._ns3i_destination4").set(index_dest_address);
        }

        if (phv->has_field("scalars.userMetadata._ns3i_port5")) {
            phv->get_field("scalars.userMetadata._ns3i_port5").set(inPort);
        }

        //std::cout << "@mingyu before bmv2 protocol " << protocol << " idx " << index_dest_address << std::endl;

        // put the bm::packet into buffer, and then goto the ingress loop.
        input_buffer->push_front(
            InputBuffer::PacketType::NORMAL, std::move(packet));
 
        // ======================================== back ============================================
        bool tex_flag = false;
        std::unique_ptr<bm::Packet> bmpkt;

        m_mutex.lock();
        if (!bm_queue.empty()){
            bmpkt = std::move(bm_queue.front());  // unique ptr move
            tex_flag = true;
            bm_queue.pop();
        }
        m_mutex.unlock();

        if (tex_flag) {
            // 存在处理的消息
            PHV* phv = bmpkt->get_phv();

            uint16_t protocol;
            if (phv->has_field("scalars.userMetadata._ns3i_protocol3")) {
                protocol = phv->get_field("scalars.userMetadata._ns3i_protocol3").get_int();
            }
            int des_idx = 0;
            if (phv->has_field("scalars.userMetadata._ns3i_destination4")) {
                des_idx = phv->get_field("scalars.userMetadata._ns3i_destination4").get_int();    
            }
            int port = 0;
            // take the port info into p4
            if (phv->has_field("standard_metadata.egress_spec")) {
                port = phv->get_field("standard_metadata.egress_spec").get_int();
            }
            if (phv->has_field("standard_metadata.egress_port")) {
                port = phv->get_field("standard_metadata.egress_port").get_int();
            }
            //std::cout << "@mingyu after bmv2 port: " << port << " protocol " << protocol << " idx " << des_idx << std::endl;
            // phv->get_field("standard_metadata.egress_port")

            void *bm2Buffer = bmpkt.get()->data();
            size_t bm2Length = bmpkt.get()->get_data_size();
            ns3::Packet ns3Packet((uint8_t*)bm2Buffer,bm2Length);
            //Ptr<ns3::Packet> packetOut(&ns3Packet);

            // === send out
            m_pNetDevice->SendNs3Packet(ns3Packet, port, protocol, destination_list[des_idx]);            
        }
    
        /*
        if (phv->has_field("scalars.userMetadata._ns3i_protocol20")) {
            Field &f_mgid = phv->get_field("scalars.userMetadata._ns3i_protocol20");
            protocol = f_mgid.get_uint();
        } else if (phv->has_field("scalars.userMetadata._ns3i_protocol16")) {
            Field &f_mgid = phv->get_field("scalars.userMetadata._ns3i_protocol16");
            protocol = f_mgid.get_uint();
        } else {
            // warning
            std::cout << "No protocol for sending ns-3 packet!" << std::endl;
            protocol = 0;
        }

        int des_idx = 0;
        if (phv->has_field("scalars.userMetadata._ns3i_destination21")) {
            des_idx = phv->get_field("scalars.userMetadata._ns3i_destination21").get_uint();
        } else if (phv->has_field("scalars.userMetadata._ns3i_destination17")) {
            des_idx = phv->get_field("scalars.userMetadata._ns3i_destination17").get_uint();
        } else {
            // warning
            std::cout << "No destnation for sending ns-3 packet!" << std::endl;
            des_idx = 0;
        }
        
        int port = 0;
        // take the port info into p4
        if (phv->has_field("scalars.userMetadata._ns3i_port22")) {
            port = phv->get_field("scalars.userMetadata._ns3i_port22").get_uint();
        } else if (phv->has_field("scalars.userMetadata._ns3i_port18")) {
            port = phv->get_field("scalars.userMetadata._ns3i_port18").get_uint();
        } else {
            // warning
            std::cout << "No port info for sending ns-3 packet!" << std::endl;
        }*/
        return 0;
    }
    return -1;
    
    /*if (phv->has_field("scalars.userMetadata._ns3i_protocol20")) {
        phv->get_field("scalars.userMetadata._ns3i_protocol20")
            .set(protocol);
    } else if (phv->has_field("scalars.userMetadata._ns3i_protocol16")) {
        phv->get_field("scalars.userMetadata._ns3i_protocol16")
            .set(protocol);
    } else {
        std::cout << "protocol set from ns3 -> bmv2 failed." << std::endl;
    }*/

    /*// test for debug
    int protocol_id = 0;
    if (phv->has_field("scalars.userMetadata._ns3i_protocol20")) {
        Field &f_mgid = phv->get_field("scalars.userMetadata._ns3i_protocol20");
            protocol_id = f_mgid.get_int();
    } else if (phv->has_field("scalars.userMetadata._ns3i_protocol16")) {
        Field &f_mgid = phv->get_field("scalars.userMetadata._ns3i_protocol16");
            protocol_id = f_mgid.get_int();
    } else {
        std::cout << "protocol set from ns3 -> bmv2 failed." << std::endl;
    }
    std::cout << "protocol_id value " << protocol_id << std::endl;*/

    // address saving and processing in ns-3 @mingyu
    
    /*
    int index_dest_address = 0;
    if (std::find(destination_list.begin(), destination_list.end(), destination) == destination_list.end()){
        destination_list.push_back(destination);
        index_dest_address = destination_list.size() - 1;
    }
    else{
        auto it = std::find(destination_list.begin(), destination_list.end(), destination);
        index_dest_address = std::distance(destination_list.begin(), it);
    }
    std::cout << "index of destadd: " << index_dest_address << " total list size: " << destination_list.size() << std::endl;

    // address index insert with p4 packages @mingyu
    if (phv->has_field("scalars.userMetadata._ns3i_destination21")) {
        phv->get_field("scalars.userMetadata._ns3i_destination21")
            .set(index_dest_address);
    } else if (phv->has_field("scalars.userMetadata._ns3i_destination17")) {
        phv->get_field("scalars.userMetadata._ns3i_destination17")
            .set(index_dest_address);
    } else {
        // warning
        std::cout << "destination address set from ns3 -> bmv2 failed." << std::endl;
    }

    // take the port info into p4
    if (phv->has_field("scalars.userMetadata._ns3i_port22")) {
        phv->get_field("scalars.userMetadata._ns3i_port22")
            .set(inPort);
    } else if (phv->has_field("scalars.userMetadata._ns3i_port18")) {
        phv->get_field("scalars.userMetadata._ns3i_port18")
            .set(inPort);
    } else {
        // warning
        std::cout << "destination port set from ns3 -> bmv2 failed." << std::endl;
    }
    */
}

int P4Model::ReceivePacketOld(Ptr<ns3::Packet> packetIn, int inPort,
    		uint16_t protocol, Address const& destination)
{
    // **************Change ns3::Packet to bm::Packet***************************
	int ns3Length = packetIn->GetSize();
	uint8_t* ns3Buffer = new uint8_t[ns3Length];
	packetIn->CopyData(ns3Buffer,ns3Length);
	std::unique_ptr<bm::Packet> packet = new_packet_ptr(inPort, m_pktID++,
		ns3Length, bm::PacketBuffer(2048, (char*)ns3Buffer, ns3Length));
	delete[] ns3Buffer;
	// *************************************************************************
	if (packet) {

		int len = packet.get()->get_data_size();
		packet.get()->set_ingress_port(inPort);
		bm::PHV *phv = packet.get()->get_phv();
		phv->reset_metadata();
		phv->get_field("standard_metadata.ingress_port").set(inPort);
		phv->get_field("standard_metadata.packet_length").set(len);

		if (phv->has_field("intrinsic_metadata.ingress_global_timestamp")) {
			phv->get_field("intrinsic_metadata.ingress_global_timestamp").set(0);
		}

		// Ingress
		bm::Parser *parser = this->get_parser("parser");
		bm::Pipeline *ingressMau = this->get_pipeline("ingress");
		phv = packet.get()->get_phv();

		parser->parse(packet.get());

		ingressMau->apply(packet.get());

		packet->reset_exit();

		bm::Field &fEgressSpec = phv->get_field("standard_metadata.egress_spec");
		int egressPort = fEgressSpec.get_int();

		// Egress
		bm::Deparser *deparser = this->get_deparser("deparser");
		bm::Pipeline *egressMau = this->get_pipeline("egress");
		fEgressSpec = phv->get_field("standard_metadata.egress_spec");
		fEgressSpec.set(0);
		egressMau->apply(packet.get());
		deparser->deparse(packet.get());

		// *************************Change bm::Packet to ns3::Packet***********************
		void *bm2Buffer = packet.get()->data();
		size_t bm2Length = packet.get()->get_data_size();
		ns3::Packet ns3Packet((uint8_t*)bm2Buffer,bm2Length);
		//Ptr<ns3::Packet> packetOut(&ns3Packet);
		// ********************************************************************************

		m_pNetDevice->SendNs3Packet(ns3Packet, egressPort, protocol, destination);

		return 0;
	}
	return -1;
}

bool P4Model::TraceAllDropInBmv2(bm::PHV* phv)
{
    /* the drop process usually done in QueueDisc, which is in the
     * traffic-control module, and with "DropBeforeEnqueue" or
     * "DropAfterDequeue" etc. Also it gives may tools like traceing,
     * drop recording etc. But here we just drop the pkts.
     *
     * In p4, the drop should add a line before the mark_to_drop, for example:
     * 		meta.drop = 1;      // add for connect ns-3 --> drop @ns3
     * 		mark_to_drop(standard_metadata);
     * In ns-3, we maybe need to trace:
     * 		scalars.userMetadata._drop18 // the name from json file data struct
     * ideas comes from: ns3-PIFO-TM
     * @todo mingyu
     */

    // The traced var name in bmv2, check the .json file get the name
    const std::string switch_1_drop_Nr = "scalars.userMetadata._ns3i_ns3_drop18";
    const std::string switch_1_queue_Id = "userMetadata._ns3i_ns3_queue_id19";
    const std::string switch_2_drop_Nr = "scalars.userMetadata._ns3i_ns3_drop14";
    const std::string switch_2_queue_Id = "userMetadata._ns3i_ns3_queue_id15";

    // the drop from switch 1 with codel1.p4
    if (phv->has_field(switch_1_drop_Nr)) {
        int mark_to_drop = phv->get_field(switch_1_drop_Nr).get_int();
        if (mark_to_drop != 0) {
            if (phv->has_field(switch_1_queue_Id)) {
                int queue_id = phv->get_field(switch_1_queue_Id).get_int();
                this->RecordAllDropInfo(queue_id); // Recored data
            } else {
                this->m_dropNum++;
                std::cout << "pkts passive droped in switch 1 bmv2-p4!" << std::endl;
            }
            return false; // drop in ns-3
        }
    }

    // the drop from switch 2 with codel2.p4
    if (phv->has_field(switch_2_drop_Nr)) {
        int mark_to_drop = phv->get_field(switch_2_drop_Nr).get_int();
        if (mark_to_drop != 0) {
            if (phv->has_field(switch_2_queue_Id)) {
                int queue_id = phv->get_field(switch_2_queue_Id).get_int();
                this->RecordAllDropInfo(queue_id); // Recored data
            } else {
                this->m_dropNum++;
                std::cout << "pkts passive droped in switch 2 bmv2-p4!" << std::endl;
            }
            return false; // drop in ns-3
        }
    }
    return true; // No drop in ns-3
}

bool P4Model::RecordAllDropInfo(int queue_id)
{
    switch (queue_id) {
    case 1: {
        this->m_qDropNum_1++;
        break;
    }
    case 2: {
        this->m_qDropNum_2++;
        break;
    }
    case 3: {
        this->m_qDropNum_3++;
        break;
    }
    default: {
        std::cout << "WARNING: No queue id, pkts initiative to be dropped in switch bmv2-p4!" << std::endl;
        break;
    }
    }
    return true;
}