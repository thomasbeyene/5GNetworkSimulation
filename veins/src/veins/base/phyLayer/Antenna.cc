#include "veins/base/phyLayer/Antenna.h"

using namespace veins;

double Antenna::getGain(Coord ownPos, Coord ownOrient, Coord otherPos)
{
    // as this base class represents an isotropic antenna, simply return 1.0
    return 1.0;
}
