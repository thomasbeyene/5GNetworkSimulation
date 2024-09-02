package BlackHoleAttack.simulations;

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.Router;
import inet.node.inet.StandardHost;
import inet.node.ethernet.EtherSwitch;
import inet.visualizer.integrated.IntegratedVisualizer;
import inet.applications.pingapp.PingApp;
import inet.linklayer.ethernet.EtherBus;
import inet.node.ethernet.EtherLink;
import org.car2x.veins.nodes.Scenario;

network ScenarioBlackHoleAttack extends Scenario
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
        dosAttacker: DosBlackHoleAttacker {
            @display("p=100,100");
            targetNode = "vehicle[0]";
            dropRate = 1.0;  // Drop all packets
            startTime = 10s;
            endTime = 90s;
        }

    connections:
        vehicle[0].out --> dosAttacker.in;
        dosAttacker.out --> lteBaseStation.in;  // Dropping packets
}