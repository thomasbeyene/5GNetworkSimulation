package jammingattacks.simulations;

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.WirelessHost;
import inet.node.inet.StandardHost;
import inet.node.inet.Router;
import inet.visualizer.integrated.IntegratedVisualizer;
import inet.physicallayer.ieee80211.packetlevel.Ieee80211DimensionalRadioMedium;
import inet.physicallayer.contract.packetlevel.IRadioMedium;
import inet.physicallayer.analogmodel.packetlevel.DimensionalAnalogModel;
import simu5g.nodes.jammers.NRJammer;

network JammingAttack extends Scenario
{
    parameters:
        int numSubnet1Clients; // number of clients in the network
        int numSubnet2Clients;
        int numSubnet3Clients;
        int numSubnet1Jammers;
        int numSubnet2Jammers;
        int numSubnet3Jammers;
    types:
        channel WirelessChannel extends Ieee80211DimensionalRadioMedium
        {
            pathLossType = "freeSpace";
            analogModel = DimensionalAnalogModel;
        }
    submodules:
        configurator: Ipv4NetworkConfigurator;
        medium: Ieee80211DimensionalRadioMedium {
            analogModel = DimensionalAnalogModel;
        }
        router[3]: Router; // predefined router
        customer[numSubnet1Clients + numSubnet2Clients + numSubnet3Clients]: WirelessHost;
        JammerHost[numSubnet1Jammers + numSubnet2Jammers + numSubnet3Jammers]: NRJammer
		{
            @display("i=device/drone");
        };
        server: StandardHost
        {
            @display("i=device/server");
        };
        visualizer: IntegratedVisualizer;
    connections allowunconnected: // network level connections
        // No direct connections needed as wireless communication is managed by the radio medium
        for i=0..2
        {
            router[i].pppg++ <--> medium <--> router[(i + 1) % 3].pppg++;
        };
        router[0].wlan++ <--> medium <--> customer[0].wlan++; // wireless
        router[1].wlan++ <--> medium <--> customer[numSubnet1Clients].wlan++; // wireless
        router[2].wlan++ <--> medium <--> customer[numSubnet1Clients + numSubnet2Clients].wlan++; // wireless
        server.wlan++ <--> medium <--> customer[numSubnet1Clients + numSubnet2Clients + numSubnet3Clients].wlan++; // wireless
        
        for i=0..numSubnet1Jammers - 1
        {
            JammerHost[i].wlan++ <--> medium <--> customer[0].wlan++; // wireless
        }
        for i=0..numSubnet2Jammers - 1
        {
            JammerHost[i + numSubnet1Jammers].wlan++ <--> medium <--> customer[numSubnet1Clients].wlan++; // wireless
        }
        for i=0..numSubnet3Jammers - 1
        {
            JammerHost[i + numSubnet1Jammers + numSubnet2Jammers].wlan++ <--> medium <--> customer[numSubnet1Clients + numSubnet2Clients].wlan++; // wireless
        }
}
