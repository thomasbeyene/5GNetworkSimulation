package ddosattacks.simulations;

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.StandardHost;
import inet.node.inet.Router;
import inet.node.ethernet.EtherSwitch;
import inet.visualizer.integrated.IntegratedVisualizer;
import inet.node.ethernet.Eth10M;

network UdpFlood
{
    parameters:
        int clients_lan1; 
        int clients_lan2;
        int clients_lan3;  
        int attackers_lan1;
        int attackers_lan2;
        int attackers_lan3;
    submodules:
        configurator: Ipv4NetworkConfigurator;
        switch[3]: EtherSwitch;
        router[3]: Router;
        user[clients_lan1 + clients_lan2 + clients_lan3]: StandardHost;
        Host[attackers_lan1 + attackers_lan2 + attackers_lan3]: StandardHost
		{
            @display("i=device/laptop,red;");
        };
        server: StandardHost
        {
            @display("i=device/server");
            @statistic[NumReceivedIpPackets](source=count(packetReceivedFromLower); record=vector);
        };
        visualizer: IntegratedVisualizer;
    connections:
        for i=0..2
        {
            router[i].ethg++ <--> Eth10M <--> router[(i + 1) % 3].ethg++;
        }
        
        for i=0..2
        {
            router[i].ethg++ <--> Eth10M <--> switch[i].ethg++;
        }
        
        for i=0..clients_lan1 - 1
        {
            user[i].ethg++ <--> Eth10M <--> switch[0].ethg++;
        }
        for i=0..attackers_lan1 - 1
        {
            Host[i].ethg++ <--> Eth10M <--> switch[0].ethg++;
        }
        
        for i=0..clients_lan2 - 1
        {
            user[i + clients_lan1].ethg++ <--> Eth10M <--> switch[1].ethg++;
        }
        for i=0..attackers_lan2 - 1
        {
            Host[i + attackers_lan1].ethg++ <--> Eth10M <--> switch[1].ethg++;
        }
        
        for i=0..clients_lan3 - 1
        {
            user[i + clients_lan1 + clients_lan2].ethg++ <--> Eth10M <--> switch[2].ethg++;
        }
        for i=0..attackers_lan3 - 1
        {
            Host[i + attackers_lan1 + attackers_lan2].ethg++ <--> Eth10M <--> switch[2].ethg++;
        }
        
        server.ethg++ <--> Eth10M <--> switch[0].ethg++;
}
