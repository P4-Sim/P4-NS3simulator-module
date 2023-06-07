Welcome to the P4Simulator wiki!

P4Simulator is a P4-driven network simulator aiming at combining P4, the state-of-the-art programmable data plane language and ns-3, one of the most popular network simulators. P4Simulator is now being developed by students at NetArch Lab at Tsinghua University. P4Simulator is an open-source project under Apache License 2.0.

Current there are some branchs:

* **master**: The origin P4Simulator developed by students at NetArch Lab at Tsinghua University. This was not updated until 2018. The process is  straightforward and can be used for learning.

* **devbmv2**: **[Recommend]** This move all the functions from [`bmv2-simple-switch`](https://github.com/p4lang/behavioral-model/tree/main/targets/simple_switch) into the `p4-model.cc` with multi-threads, support all the features of `bmv2-simple-switch`(without thrift server), which makes a hybrid simulator. The time is still using system time in `p4-switch`.

* **mulit**: This is after the **devbmv2** and replace all the `std::threads` with `Simulator::Schedule`(Localization). Replace the system with ns-3 time. There is a lot of work waiting to be done. Current is not finished.

* **devmmy**: branch by Mingyu for development.