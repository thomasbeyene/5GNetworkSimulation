package JammingAttack.simulations;

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.Router;
import inet.node.inet.StandardHost;
import inet.node.ethernet.EtherSwitch;
import inet.visualizer.integrated.IntegratedVisualizer;
import inet.applications.pingapp.PingApp;
import inet.linklayer.ethernet.EtherBus;
import inet.node.ethernet.EtherLink;

network ScenarioJammingAttack
{
    submodules:
        vehicle[10]: Vehicle {
            // Vehicle-specific parameters
        }
        rsu: RSU {
            // RSU parameters
        }
        lteBaseStation: LteBaseStation {
            // 5G base station parameters
        }
        coreNetwork: LteCoreNetwork {
            // Core network parameters
        }
        dosAttacker: DosJammingAttacker {
            @display("p=100,100");
            jammingPower = 100mW;
            targetFrequency = "2.4GHz";
            jamDuration = 50s;
        }

    connections:
        vehicle[0].out --> rsu.in;
        rsu.out --> lteBaseStation.in;
        dosAttacker.out --> rsu.in;
}