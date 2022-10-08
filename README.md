# ipstat_monitor
Collector of the traffic on the basis of pcap-library. 

Data are aggregated and saved under the scheme "DetailHostMatrix Aggregation Schemes" Cisco NetFlow FlowCollector. 

Data are kept in the form of gzip-files or deduced in stdout.

**DetailHostMatrix:**

The output of the DetailHostMatrix aggregation scheme consists of one record for each unique combination of source IP address, destination IP address, source port, destination port, and protocol present in the flow data received by FlowCollector during the current collection period. Each output record contains the following fields:

Key field:

srcaddr, dstaddr, srcport, dstport, protocol

Value fields:

packet count, byte count, flow count, firstTimeStamp, lastTimeStamp

