package org.car2x.veins.base.modules;


simple BaseLayer
{
    parameters:
        @class(veins::BaseLayer);
        bool notAffectedByHostState = default(false);
        
    gates:
        input upperLayerIn; // from upper layer
        output upperLayerOut; // to uppe layer
        input upperControlIn; // control from upper layer
        output upperControlOut; // control to upper layer
        input lowerLayerIn; // from lower layer
        output lowerLayerOut; // to lower layer
        input lowerControlIn; // control from lower layer
        output lowerControlOut; // control to lower layer
}
