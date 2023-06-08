# include "ns3/log.h"
# include "ns3/global.h"

namespace ns3 {

  NS_LOG_COMPONENT_DEFINE("P4GlobalVar");
  NS_OBJECT_ENSURE_REGISTERED(P4GlobalVar);

  P4Controller P4GlobalVar::g_p4Controller;

  // init default static global variable
  unsigned int P4GlobalVar::g_networkFunc=SIMPLESWITCH;
  std::string P4GlobalVar::g_flowTablePath=""; // SET BY HAND BEFORE USING
  std::string P4GlobalVar::g_viewFlowTablePath="";
  std::string P4GlobalVar::g_p4MatchTypePath="";
  unsigned int P4GlobalVar::g_populateFlowTableWay=RUNTIME_CLI; // LOCAL_CALL/RUNTIME_CLI
  std::string P4GlobalVar::g_p4JsonPath="";

  std::string P4GlobalVar::g_homePath="/home/p4/";
  std::string P4GlobalVar::g_ns3RootName="/";
  std::string P4GlobalVar::g_ns3SrcName="p4simulator/";  
  std::string P4GlobalVar::g_nfDir=P4GlobalVar::g_homePath+P4GlobalVar::g_ns3RootName+P4GlobalVar::g_ns3SrcName+"scratch-p4-file/p4src";
  std::string P4GlobalVar::g_topoDir=P4GlobalVar::g_homePath+P4GlobalVar::g_ns3RootName+P4GlobalVar::g_ns3SrcName+"scratch-p4-file/topo/";
  std::string P4GlobalVar::g_flowTableDir=P4GlobalVar::g_homePath+P4GlobalVar::g_ns3RootName+P4GlobalVar::g_ns3SrcName+"scratch-p4-file/flowtable/";
  
  unsigned int P4GlobalVar::g_nsType=P4Simulator;
  unsigned int P4GlobalVar::g_runtimeCliTime=3;
  std::map<std::string,unsigned int> P4GlobalVar::g_nfStrUintMap;

  // configuration for the ns3-->p4
  std::string P4GlobalVar::ns3i_drop_1 = "scalars.userMetadata._ns3i_ns3_drop18";
  std::string P4GlobalVar::ns3i_drop_2 = "scalars.userMetadata._ns3i_ns3_drop14";
  std::string P4GlobalVar::ns3i_priority_id_1 = "scalars.userMetadata._ns3i_ns3_priority_id19";
  std::string P4GlobalVar::ns3i_priority_id_2 = "scalars.userMetadata._ns3i_ns3_priority_id15";
  std::string P4GlobalVar::ns3i_protocol_1 = "scalars.userMetadata._ns3i_protocol20";
  std::string P4GlobalVar::ns3i_protocol_2 = "scalars.userMetadata._ns3i_protocol16";
  std::string P4GlobalVar::ns3i_destination_1 = "scalars.userMetadata._ns3i_destination21";
  std::string P4GlobalVar::ns3i_destination_2 = "scalars.userMetadata._ns3i_destination17";
  std::string P4GlobalVar::ns3i_pkts_id_1 = "scalars.userMetadata._ns3i_pkts_id22";
  std::string P4GlobalVar::ns3i_pkts_id_2 = "scalars.userMetadata._ns3i_pkts_id18";

  // tracing info
	bool P4GlobalVar::ns3_p4_tracing_dalay_sim = false; // Byte Tag
	bool P4GlobalVar::ns3_p4_tracing_dalay_emu = false; // system time 
	bool P4GlobalVar::ns3_p4_tracing_control = false; // how the switch control the pkts
	bool P4GlobalVar::ns3_p4_tracing_drop = false; // the pkts drop in and out switch

  unsigned long getTickCount(void)
  {
    unsigned long currentTime=0;
    #ifdef WIN32
      currentTime = GetTickCount();
    #endif
      struct timeval current;
      gettimeofday(&current, NULL);
      currentTime = current.tv_sec * 1000 + current.tv_usec / 1000;
    #ifdef OS_VXWORKS
      ULONGA timeSecond = tickGet() / sysClkRateGet();
      ULONGA timeMilsec = tickGet() % sysClkRateGet() * 1000 / sysClkRateGet();
      currentTime = timeSecond * 1000 + timeMilsec;
    #endif
    return currentTime;
  }

  void P4GlobalVar::SetP4MatchTypeJsonPath()
  {
    switch (P4GlobalVar::g_networkFunc)
    {
      // simple switch for new p4-model
      case SIMPLESWITCH: {
        P4GlobalVar::g_p4JsonPath = P4GlobalVar::g_nfDir + "simple_switch/simple_switch.json";
        P4GlobalVar::g_p4MatchTypePath = P4GlobalVar::g_nfDir + "simple_switch/mtype.txt";
        P4GlobalVar::g_flowTableDir = P4GlobalVar::g_nfDir + "simple_switch/flowtable/";
        break;
      }
      case PRIORITYQUEUE: {
        P4GlobalVar::g_p4JsonPath = P4GlobalVar::g_nfDir + "priority_queuing/priority_queuing.json";
        P4GlobalVar::g_p4MatchTypePath = P4GlobalVar::g_nfDir + "priority_queuing/mtype.txt";
        P4GlobalVar::g_flowTableDir = P4GlobalVar::g_nfDir + "priority_queuing/flowtable/";
        break;
      }
      case SIMPLECODEL: {
        P4GlobalVar::g_p4JsonPath = P4GlobalVar::g_nfDir + "simple_codel/simple_codel.json";
        P4GlobalVar::g_p4MatchTypePath = P4GlobalVar::g_nfDir + "simple_codel/mtype.txt";
        P4GlobalVar::g_flowTableDir = P4GlobalVar::g_nfDir + "simple_codel/flowtable/";
        break;
      }
      case CODELPP: {
        P4GlobalVar::g_p4JsonPath = P4GlobalVar::g_nfDir + "codelpp/codel1.json";
        // here we just config for the first switch
        P4GlobalVar::g_p4MatchTypePath = P4GlobalVar::g_nfDir + "codelpp/mtype.txt";
        P4GlobalVar::g_flowTableDir = P4GlobalVar::g_nfDir + "codelpp/flowtable/";
        break;
      }
      default: {
        std::cerr << "NETWORK_FUNCTION_NO_EXIST!!!" << std::endl;
        break;
      }
    }
  } 

  void P4GlobalVar::InitNfStrUintMap()
  {
    P4GlobalVar::g_nfStrUintMap["SIMPLESWITCH"]=SIMPLESWITCH;
    P4GlobalVar::g_nfStrUintMap["PRIORITYQUEUE"]=PRIORITYQUEUE;
    P4GlobalVar::g_nfStrUintMap["SIMPLECODEL"]=SIMPLECODEL;
    P4GlobalVar::g_nfStrUintMap["CODELPP"]=CODELPP;
  }

  TypeId P4GlobalVar::GetTypeId(void)
  {
	  static TypeId tid = TypeId("ns3::P4GlobalVar")
		  .SetParent<Object>()
		  .SetGroupName("P4GlobalVar")
		  ;
	  return tid;
  }
  P4GlobalVar::P4GlobalVar()
  {
	  NS_LOG_FUNCTION(this);
  }

  P4GlobalVar::~P4GlobalVar()
  {
	  NS_LOG_FUNCTION(this);
  }
}
