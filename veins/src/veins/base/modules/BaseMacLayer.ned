package org.car2x.veins.base.modules;

simple BaseMacLayer extends BaseLayer like IWirelessMac
{
    parameters:
        @class(veins::BaseMacLayer);
        int    headerLength @unit(bit);           // length of the MAC packet header (in bits)
        string address = default("auto");         // MAC address as hex string (12 hex digits), or
                                                  // "auto". "auto" values will be replaced by
                                                  // a generated MAC address in init stage 1.
}
