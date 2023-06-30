P4-NS3 Simulator is a P4-driven network simulator aiming at combining P4, the state-of-the-art programmable data plane language and ns-3, one of the most popular network simulators. P4-NS3 Simulator is an open-source project under Apache License 2.0.

## Current branchs

* **master**: The origin P4Simulator. This is the old version only support P4-14 with last update in 2018. The process is simple and only support the basic routing etc features.

* **devbmv2**: **[Recommend]** from teams of TU Dresden. This move all the functions from [`bmv2-simple-switch`](https://github.com/p4lang/behavioral-model/tree/main/targets/simple_switch) into the `p4-model.cc` with multi-threads, support all the features of `bmv2-simple-switch`(without thrift server), which makes a hybrid simulator. The time is still using system time in `p4-switch`.
    * Fast and automaticly build network topo in ns-3 with `text` file.
    * Support the P4-verison 16.
    * Integrate the `BMv2-simple-switch` with all features: [Supported primitive actions](https://github.com/p4lang/behavioral-model/blob/main/docs/simple_switch.md#supported-primitive-actions).
    More detail see [simple_switch-readme](https://github.com/p4lang/behavioral-model/blob/main/docs/simple_switch.md).
    * Command text can add the flow-table or other settings by ipc. Support see [table-match-kinds-supported](https://github.com/p4lang/behavioral-model/blob/main/docs/simple_switch.md#table-match-kinds-supported).

* **mulit**: This is after the devbmv2 and replace all the `std::threads` with `Simulator::Schedule`(Localization). Replace the system with ns-3 time. There is a lot of work waiting to be done. Current is not finished.

* **devmmy**: private branch by developer for development.

## Get start!

1. Install module into ns-3. see [NS3-p4simulator-install](https://github.com/Mingyumaz/NS3-p4simulator-install)
