
package org.car2x.veins.base.modules;


simple BaseMobility like IMobility
{
    parameters:
        @class(veins::BaseMobility);
        bool notAffectedByHostState = default(true);
        double x; // x coordinate of the nodes' position (-1 = random)
        double y; // y coordinate of the nodes' position (-1 = random)
        double z; // z coordinate of the nodes' position (-1 = random)
        double xOrientation = default(1);
        double yOrientation = default(0);
        double zOrientation = default(0);
        @signal[org_car2x_veins_base_modules_mobilityStateChanged](type="veins::BaseMobility");
        @display("i=block/cogwheel");
}

