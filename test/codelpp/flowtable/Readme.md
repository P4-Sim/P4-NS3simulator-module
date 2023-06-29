在各个命令中间不要留有空行：
不然会出现：（会造成空行前的commandline被执行多次（一个空行 -> 两次）)
```
 10 RuntimeCmd: Setting default action of forward_table
 11 action:              drop
 12 runtime data:        
 13 RuntimeCmd: Setting default action of forward_table
 14 action:              drop

101 RuntimeCmd: Adding entry to exact match table forward_table                                                                                                                                                                                                                         
102 match key:           EXACT-0a:01:00:03
103 action:              set_port
104 runtime data:        00:00
105 Entry has been added with handle 5
106 RuntimeCmd: Adding entry to exact match table forward_table
107 match key:           EXACT-0a:01:00:03
108 action:              set_port
109 runtime data:        00:00
110 Invalid table operation (DUPLICATE_ENTRY)
```