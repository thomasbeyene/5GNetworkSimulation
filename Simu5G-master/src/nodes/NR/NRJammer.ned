package simu5g.nodes.NR;

import simu5g.nodes.jammerNode;

// 
// gNodeB Module
//
module NRJammer extends jammerNode
{
    parameters:
        @networkNode();
        @display("i=device/drone");
		StatsCollectorType = default("GNodeBStatsCollector"); 
        gateway = default("upf");
        nodeType = "GNODEB";        // DO NOT CHANGE
        nicType = default("NRNicEnb");
}