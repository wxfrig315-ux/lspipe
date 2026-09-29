#pragma once
#include "ISerializable.h"
#include "utils.h"
#include <algorithm>

class AV_PAIR : public ISerializable
{
public:
    AV_PAIR();
    AV_PAIR(std::vector<uint8_t> vByteBuffer);
    ~AV_PAIR() = default;
    uint16_t AvId;
    uint16_t AvLen;
    std::vector<uint8_t> Value;
    std::vector<uint8_t> serialize() override;
    bool deserialize(const std::vector<uint8_t>& vByteBuffer) override;


};

class AttributeMap: public ISerializable
{
public:
    enum AvId
    {
        MsvAvEOL = 0x0,
        MsvAvNbComputerName = 0x1,
        MsvAvNbDomainName = 0x2,
        MsvAvDnsComputerName = 0x3,
        MsvAvDnsDomainName = 0x4,
        MsvAvDnsTreeName = 0x5,
        MsvAvFlags = 0x6,
        MsvAvTimestamp = 0x7,
        MsvAvSingleHost = 0x8,
        MsvAvTargetName = 0x9,
        MsvAvChannelBindings = 0xA

    };
	AttributeMap();
	~AttributeMap() = default;
    std::vector<AV_PAIR> data;
    std::vector<uint8_t> getItem(uint8_t id);
    std::vector<uint8_t> serialize() override;
    bool deserialize(const std::vector<uint8_t> &vByteBuffer) override;
private:

};

