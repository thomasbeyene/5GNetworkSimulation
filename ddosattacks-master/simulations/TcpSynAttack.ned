package ddosattacks.simulations;

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.Router;
import inet.node.inet.StandardHost;
import inet.node.ethernet.EtherSwitch;
import inet.visualizer.integrated.IntegratedVisualizer;
import inet.applications.pingapp.PingApp;
import inet.linklayer.ethernet.EtherBus;
import inet.node.ethernet.EtherLink;
import org.car2x.veins.nodes.Scenario;

network TcpSynAttack extends Scenario
{
    parameters:
        int numSubnet1Attackers;
        int numSubnet2Attackers;
        int numSubnet3Attackers;
    types:
        channel Eth1M extends EtherLink
        {
            length = 20m;
        	datarate = 1Mbps;
        }
        channel Eth500K extends EtherLink
        {
            length = 20m;
        	datarate = 0.5Mbps;
        }
    submodules:
        configurator: Ipv4NetworkConfigurator;
        switch[3]: EtherSwitch;
        router[3]: Router; // predefined router
        Host[numSubnet1Attackers + numSubnet2Attackers + numSubnet3Attackers]: StandardHost
		{
            @display("i=device/laptop,red;");
        };
        server: StandardHost
        {
            @display("i=device/server");
            @statistic[NumReceivedIpPackets](source=count(packetReceivedFromLower); record=vector);
        };
        visualizer: IntegratedVisualizer;
    connections: // network level connections
        for i=0..2
        {
            router[i].pppg++ <--> Eth500K <--> router[(i + 1) % 3].pppg++;
        };
        router[0].ethg++ <--> Eth1M <--> switch[0].ethg++;
        router[1].ethg++ <--> Eth1M <--> switch[1].ethg++;
        router[2].ethg++ <--> Eth1M <--> switch[2].ethg++;
        server.ethg++ <--> Eth1M <--> switch[1].ethg++;
        for i=0..numSubnet1Attackers - 1
        {
            Host[i].ethg++ <--> Eth1M <--> switch[0].ethg++; // ethernet
        }
        for i=0..numSubnet2Attackers - 1
        {
            Host[i + numSubnet1Attackers].ethg++ <--> Eth1M <--> switch[1].ethg++; // ethernet
        }
        for i=0..numSubnet3Attackers - 1
        {
            Host[i + numSubnet1Attackers + numSubnet2Attackers].ethg++ <--> Eth1M <--> switch[2].ethg++; // ethernet
        }
}
