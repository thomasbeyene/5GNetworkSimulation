package org.car2x.veins.base.modules;

moduleinterface ITrafficLightLogic
{
    parameters:
        @display("i=block/classifier");
    gates:
        inout interface;
        inout applLayer;
}
