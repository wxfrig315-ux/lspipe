#include "DirectTCPTransportHeader.h"

void DirectTCPTransportHeader::setLength(uint32_t length)
{
    this->StreamProtocolLength[0] = (length >> 16) & 0xFF;
    this->StreamProtocolLength[1] = (length >> 8) & 0xFF;
    this->StreamProtocolLength[2] = length & 0xFF;
}
uint32_t DirectTCPTransportHeader::getLength()
{
        return (static_cast<uint32_t>(this->StreamProtocolLength[0]) << 16) |
            (static_cast<uint32_t>(this->StreamProtocolLength[1]) << 8) |
            (static_cast<uint32_t>(this->StreamProtocolLength[2]));
}
std::vector<uint8_t> DirectTCPTransportHeader::serialize() 
{
    std::vector<uint8_t> res(4);
    res[0] = (this->Zero);
    res[1] = this->StreamProtocolLength[0];
    res[2] = this->StreamProtocolLength[1];
    res[3] = this->StreamProtocolLength[2];
    return res;
}

bool DirectTCPTransportHeader::deserialize(const std::vector<uint8_t>& vByteBuffer)
{
    this->Zero = vByteBuffer[0];
    this->StreamProtocolLength[0] = vByteBuffer[1];
    this->StreamProtocolLength[1] = vByteBuffer[2];
    this->StreamProtocolLength[2] = vByteBuffer[3];
    return true;
}

DirectTCPTransportHeader::DirectTCPTransportHeader():Zero(0)
{
    this->StreamProtocolLength.assign(3, 0);
}
