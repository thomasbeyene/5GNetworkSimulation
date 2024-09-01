package org.car2x.veins.base.modules;

simple BaseWorldUtility
{
    parameters:
        @class(veins::BaseWorldUtility);
        double playgroundSizeX @unit(m);    // x size of the area the nodes are in (in meters)
        double playgroundSizeY @unit(m);    // y size of the area the nodes are in (in meters)
        double playgroundSizeZ @unit(m);    // z size of the area the nodes are in (in meters)
        bool   useTorus = default(false);   // use the playground as torus?
        bool   use2D    = default(false);   // use a 2-dimensional world?
        @display("i=misc/globe");
}

