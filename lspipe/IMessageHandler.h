#pragma once
#include "SMB2BasePacket.h"

class IMessageHandler 
{
public:
    virtual void messageHandle(const std::vector<uint8_t> &vByteBuffer) = 0;
    virtual ~IMessageHandler() {}
};