#pragma once
#include<vector>
#include "ISerializable.h"
#include "utils.h"

#pragma pack(push,1)

struct FieldDescriptor
{
    uint16_t len = 0;
    uint16_t maxLen = 0;
    uint32_t offset = 0;
};

#pragma pack (pop)

class NTLMType1Message : public ISerializable
{
public:
    NTLMType1Message();
    ~NTLMType1Message() = default;
    uint64_t Signature;
    uint32_t MessageType;
    uint32_t NegotiateFlags;
    FieldDescriptor Domain;
    FieldDescriptor WorkStation;
    uint64_t Version;
    std::vector<uint8_t> Payload;

    std::vector<uint8_t> serialize() override;
    bool deserialize(const std::vector<uint8_t> &vByteBuffer) override;
private:

};

class NTLMType2Message: public ISerializable
{
public:
    uint64_t Signature;
    uint32_t MessageType;
    FieldDescriptor TargetNameFields;
    uint32_t NegotiateFlags;
    std::vector<uint8_t> ServerChall;
    uint64_t Reserved;
    FieldDescriptor TargetInfoFields;
    uint64_t Version;
    std::vector<uint8_t> vTargetName;
    std::vector<uint8_t> vTargetInfo;
    NTLMType2Message();
    ~NTLMType2Message() = default;

    bool deserialize(const std::vector<uint8_t>& vByteBuffer) override;

private:

};

class NTLMType3Message : public ISerializable
{
public:
    uint64_t Signature;
    uint32_t MessageType;
    FieldDescriptor LmChallengeResponseFields;
    FieldDescriptor NtChallengeResponseFields;
    FieldDescriptor DomainNameFields;
    FieldDescriptor UserNameFields;
    FieldDescriptor WorkstationFields;
    FieldDescriptor EncryptedRandomSessionKeyFields;
    uint32_t NegotiateFlags;
    uint64_t Version;
    std::vector<uint8_t> MIC;
    std::vector<uint8_t> Payload;
    
    NTLMType3Message();
    ~NTLMType3Message() = default;

    std::vector<uint8_t> serialize() override;
private:

};
