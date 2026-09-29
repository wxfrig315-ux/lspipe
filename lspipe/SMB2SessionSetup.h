#pragma once

#include <vector>
#include <algorithm>
#include "ntlm.h"
#include "spnego.h"
#include "BcryptHmac.h"
#include "SMB2Header.h"
#include "SMB2BasePacket.h"
#include "AV_PAIR.h"
#include "IMessageHandler.h"
#include <algorithm>
#include "SMB2Header.h"
#include "NtlmCalcCrypto.h"

class SMB2SessionSetup :public  SMB2Header
{
public:

    uint16_t StructureSize;
    uint8_t  Flags;
    uint8_t  SecurityMode;
    uint32_t Capabilities;
    uint32_t Channel;
    uint16_t SecurityBufferOffset;
    uint16_t SecurityBufferLength;
    uint64_t PreviousSessionId;

    SMB2SessionSetup(); // Constructor
    SMB2SessionSetup(std::vector<uint8_t> vByteBuffer); // Constructor
    ~SMB2SessionSetup() = default; 

    std::vector<uint8_t> serialize() override; // Serialize packet
    bool deserialize(const std::vector<uint8_t>& vByteBuffer) override;
};



class SMB2SessionSetupRequest : public SMB2SessionSetup , public IMessageHandler
{
public:
    SMB2SessionSetupRequest();
    ~SMB2SessionSetupRequest() = default;
    NTLMType1Message msg;
    bool generatePayload(std::wstring workstation =L"", std::wstring domain = L"", uint64_t version =0);
    std::vector<uint8_t> serialize() override; // Serialize packet
    bool deserialize(const std::vector<uint8_t>& vByteBuffer) override;
    void  messageHandle(const std::vector<uint8_t>& vByteBuffer)override;
    std::vector<uint8_t> buildSMB2SessionSetupRequestPacket();

private:

};


class SMB2SessionSetupAuth: public SMB2SessionSetup, public IMessageHandler
{
public:
    SMB2SessionSetupAuth();
    SMB2SessionSetupAuth(std::wstring username, std::wstring password);
    ~SMB2SessionSetupAuth() = default;

    std::wstring username;
    std::wstring password;
    std::wstring domain;

    NTLMType2Message serverMsg;
    NTLMType3Message clientMsg;
    std::vector<uint8_t> payload;
    std::vector<uint8_t> ntHash;

    bool generatePayload(std::vector<uint8_t> NTLMv2Hash, std::vector<uint8_t> sessionKey);
    std::vector<uint8_t> serialize() override; // Serialize packet
    void  messageHandle(const std::vector<uint8_t>& vByteBuffer) override;
    std::vector<uint8_t> buildSMB2SessionSetupAuthPacket();
private:

};
