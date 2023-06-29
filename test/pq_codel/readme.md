# problem

```
scalars.userMetadata._codel_queue_id13 = -1
# 其中的queue_id未分配
```


## Compile Command

1. compile the p4 with version 14 `p4c-bmv2 --json simple_router.json simple_router.p4`

2. make conversion between P4 14 and P4 16 automate, see [website](https://github.com/p4lang/p4c/issues/893):

* p14 --> p16 [yes]
* p16 --> p14 [no]

with command `p4test --p4v 14 --pp simple_router_16.p4 simple_router.p4`

3. compile the p4 with version 16 `p4c --target bmv2 --arch v1model simple_router_16.p4`

## Implement for version 16

1. Currently installed bmv2 software supports version16 and version14.
2. I don't think the interface will change dramatically.
3. The paper claims that version16 can be used.

### step

```
1. change mark_to_drop to drop, and the parameters should be null, like that:
    "op" : "drop",
        "parameters" : [],
2. 
```

###
```
table_add t_codel_control_law a_codel_control_law 0x00000000/17 => 781
table_add t_codel_control_law a_codel_control_law 0x00000000/18 => 1104
table_add t_codel_control_law a_codel_control_law 0x00000000/19 => 1562
table_add t_codel_control_law a_codel_control_law 0x00000000/20 => 2209
table_add t_codel_control_law a_codel_control_law 0x00000000/21 => 3125
table_add t_codel_control_law a_codel_control_law 0x00000000/22 => 4419
table_add t_codel_control_law a_codel_control_law 0x00000000/23 => 6250
table_add t_codel_control_law a_codel_control_law 0x00000000/24 => 8838
table_add t_codel_control_law a_codel_control_law 0x00000000/25 => 12500
table_add t_codel_control_law a_codel_control_law 0x00000000/26 => 17677
table_add t_codel_control_law a_codel_control_law 0x00000000/27 => 25000
table_add t_codel_control_law a_codel_control_law 0x00000000/28 => 35355
table_add t_codel_control_law a_codel_control_law 0x00000000/29 => 50000
table_add t_codel_control_law a_codel_control_law 0x00000000/30 => 70710
table_add t_codel_control_law a_codel_control_law 0x00000000/31 => 100000
table_add t_codel_control_law a_codel_control_law 0x00000000/32 => 100000
```

上面t_codel_control_law中，匹配为drop_cnt，上次丢弃的数量，如果多的话，需要检查时间间隔小一些（极有可能还会拥塞->丢包）
从上到下匹配丢包数量从大到小，时间长度因此从小到大。

table_add t_codel_control_law a_codel_control_law 0x0000ffff/17 => 0x30d   // 781
table_add t_codel_control_law a_codel_control_law 0x00007fff/18 => 0x450   // 1104
table_add t_codel_control_law a_codel_control_law 0x00003fff/19 => 0x61a   // 1562
table_add t_codel_control_law a_codel_control_law 0x00001fff/20 => 0x8a1   // 2209
table_add t_codel_control_law a_codel_control_law 0x00000fff/21 => 0xc35   // 3125
table_add t_codel_control_law a_codel_control_law 0x000007ff/22 => 0x1143  // 4419
table_add t_codel_control_law a_codel_control_law 0x000003ff/23 => 0x186a  // 6250
table_add t_codel_control_law a_codel_control_law 0x000001ff/24 => 0x2286  // 8838
table_add t_codel_control_law a_codel_control_law 0x000000ff/25 => 0x30d4  // 12500
table_add t_codel_control_law a_codel_control_law 0x0000007f/26 => 0x450d  // 17677
table_add t_codel_control_law a_codel_control_law 0x0000003f/27 => 0x61a8  // 25000
table_add t_codel_control_law a_codel_control_law 0x0000001f/28 => 0x8a1b  // 35355
table_add t_codel_control_law a_codel_control_law 0x0000000f/29 => 0xc350  // 50000
table_add t_codel_control_law a_codel_control_law 0x00000007/30 => 0x11436 // 70710
table_add t_codel_control_law a_codel_control_law 0x00000003/31 => 0x186a0 // 100000

## test the command with CLI

This part will test whether the command line is correct.
for example test with `table_add t_codel_control_law a_codel_control_law 0/17 => 0x30d`

```
// in #1 shell, start the bmv2 with thrift and log in shell
sudo simple_switch --log-console --dump-packet-data 10000 -i 0@veth0 -i 1@veth2 -i 2@veth4 -i 3@veth6 -i 4@veth8 -i 5@veth10 -i 6@veth12 -i 7@veth14 routerdev1.json

// in #2 shell, run CLI and connect to the thrift port
simple_switch_CLI

// in command line CLI

RuntimeCmd: table_set_default t_codel_control_law a_codel_control_law 0x228
Setting default action of t_codel_control_law
action:              a_codel_control_law
runtime data:        00:00:00:00:02:28
RuntimeCmd: table_add t_codel_control_law a_codel_control_law 0/17 => 0x30d
Adding entry to lpm match table t_codel_control_law
match key:           LPM-00:00:00:00/17
action:              a_codel_control_law
runtime data:        00:00:00:00:03:0d
Entry has been added with handle 0
RuntimeCmd: table_add t_codel_control_law a_codel_control_law 0/19 => 1562
Adding entry to lpm match table t_codel_control_law
match key:           LPM-00:00:00:00/19
action:              a_codel_control_law
runtime data:        00:00:00:00:06:1a
Entry has been added with handle 2
```

## test the `runtime_CLI.py` interface

After we have the right command line, check that whether the python script (the function we want to copy) has the correct interface.


## test with method from `ns3-PIFO-TM`


```
    BaseP4Pipe::run_cli(std::string commandsFile) {
    int port = get_runtime_port();
    bm_runtime::start_server(this, port);
    start_and_return();

    std::this_thread::sleep_for(std::chrono::seconds(5));

    // Run the CLI commands to populate table entries
    std::string cmd = "run_bmv2_CLI --thrift_port " + std::to_string(port) + " " + commandsFile;
    std::system (cmd.c_str());
    }
```