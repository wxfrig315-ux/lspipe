#include "SMB2SessionSetup.h"




SMB2SessionSetup::SMB2SessionSetup()
    : StructureSize(25), Flags(0), SecurityMode(1),
    Capabilities(0), Channel(0), SecurityBufferOffset(0),
    SecurityBufferLength(0), PreviousSessionId(0)
{

}

SMB2SessionSetup::SMB2SessionSetup(std::vector<uint8_t> vByteBuffer)
{
    if (vByteBuffer.empty() == false)
    {
        deserialize(vByteBuffer);
    }
}


std::vector<uint8_t> SMB2SessionSetup::serialize()
{
    std::vector<uint8_t> result;

    appendLE(result, StructureSize);
    appendLE(result, Flags);
    appendLE(result, SecurityMode);
    appendLE(result, Capabilities);
    appendLE(result, Channel);
    appendLE(result, SecurityBufferOffset);
    appendLE(result, SecurityBufferLength);
    appendLE(result, PreviousSessionId);
    
    return result;
}

bool SMB2SessionSetup::deserialize(const std::vector<uint8_t>& vByteBuffer)
{
    SMB2Header::deserialize(vByteBuffer);
    size_t offset = 64;

    std::memcpy(&this->StructureSize, vByteBuffer.data() + offset, sizeof(this->StructureSize));
    offset += sizeof(this->StructureSize);
    std::memcpy(&this->Flags, vByteBuffer.data() + offset, sizeof(this->Flags));
    offset += sizeof(this->Flags);
    std::memcpy(&this->SecurityMode, vByteBuffer.data() + offset, sizeof(this->SecurityMode));
    offset += sizeof(this->SecurityMode);
    std::memcpy(&this->Capabilities, vByteBuffer.data() + offset, sizeof(this->Capabilities));
    offset += sizeof(this->Capabilities);
    std::memcpy(&this->Channel, vByteBuffer.data() + offset, sizeof(this->Channel));
    offset += sizeof(this->Channel);
    std::memcpy(&this->SecurityBufferOffset, vByteBuffer.data() + offset, sizeof(this->SecurityBufferOffset));
    offset += sizeof(this->SecurityBufferOffset);
    std::memcpy(&this->SecurityBufferLength, vByteBuffer.data() + offset, sizeof(this->SecurityBufferLength));
    offset += sizeof(this->SecurityBufferLength);
    std::memcpy(&this->PreviousSessionId, vByteBuffer.data() + offset, sizeof(this->PreviousSessionId));
    offset += sizeof(this->PreviousSessionId);

    return true;
}


SMB2SessionSetupRequest::SMB2SessionSetupRequest()
{
}
bool SMB2SessionSetupRequest::generatePayload(std::wstring workstation, std::wstring domain, uint64_t version)
{
    size_t offset = 32;
    if (version != 0)
    {
        offset += 4;
        msg.Version = version;
    }
    
    if (workstation.empty() == false)
    {
        std::vector<uint8_t> vWorkStation = wstringToBytes(workstation);
        msg.WorkStation.len = msg.WorkStation.maxLen = static_cast<uint16_t>(vWorkStation.size());
        msg.WorkStation.offset = static_cast<uint16_t>(offset);
        offset += workstation.size();
    }

    if (domain.empty() == false)
    {
        std::vector<uint8_t> vDomain = wstringToBytes(domain);
        msg.Domain.len = msg.Domain.maxLen = static_cast<uint16_t>(vDomain.size());
        msg.Domain.offset = static_cast<uint16_t>(offset);
        offset += vDomain.size();
    }

    return true;
}
std::vector<uint8_t> SMB2SessionSetupRequest::serialize()
{
    std::vector<uint8_t> result;
    
    SPNEGO_NegTokenInit token;
    token.fields[L"MechToken"] = msg.serialize();

    // Token NTLMSSP
    std::vector<uint8_t> tmp = token.getData();
    
    // Set offset and length token
    this->SecurityBufferLength = static_cast<uint16_t>(tmp.size());
    this->SecurityBufferOffset = 0x58;

    result = SMB2SessionSetup::serialize();
    result = concat(result, tmp);

    this->CreditCharge = calcCreditCharge(result.size());
    return result;
}
bool SMB2SessionSetupRequest::deserialize(const std::vector<uint8_t>& vByteBuffer)
{
    return false;
}
void SMB2SessionSetupRequest::messageHandle(const std::vector<uint8_t>& vByteBuffer)
{
    SMB2Header::deserialize(vByteBuffer);

    this->Command = 1;
    this->MessageId += 1;
    SMB2Header::Flags = 0;
}

std::vector<uint8_t> SMB2SessionSetupRequest::buildSMB2SessionSetupRequestPacket()
{
    std::vector<uint8_t> result = SMB2SessionSetupRequest::serialize();
   
    result = concat(SMB2Header::serialize(), result);

    return result;
}

SMB2SessionSetupAuth::SMB2SessionSetupAuth()
{
}
SMB2SessionSetupAuth::SMB2SessionSetupAuth(std::wstring username, std::wstring password):username(username),
password(password)
{
    ntHash.clear();
}
std::vector<uint8_t> SMB2SessionSetupAuth::serialize()
{
    std::vector<uint8_t> result;
    SMB2SessionSetup::SecurityBufferOffset = 0x58;
    SMB2SessionSetup::SecurityBufferLength = payload.size();
    result = SMB2SessionSetup::serialize();
    result = concat(result, payload);
   
    return result;
}


std::vector<uint8_t> SMB2SessionSetupAuth::buildSMB2SessionSetupAuthPacket()
{
    std::vector<uint8_t> result = SMB2SessionSetupAuth::serialize();
    
    result = concat(SMB2Header::serialize(), result);
    return result;
}

void SMB2SessionSetupAuth::messageHandle(const std::vector<uint8_t>& vByteBuffer)
{

    SMB2Header::deserialize(vByteBuffer);
    SMB2Header::Command = 1;
    SMB2Header::MessageId += 1;
    SMB2Header::Flags = 0;
    SMB2Header::CreditRequest = 130;
    SMB2Header::CreditCharge = 0;
    SMB2Header::Reserved = 0;
    SMB2Header::Reserved2 = 0;
    SMB2Header::NextCommand = 0;
    

    std::string target_str = "NTLMSSP";
    std::vector<uint8_t> target(target_str.begin(), target_str.end());

    std::vector<uint8_t>::const_iterator  it = std::search(vByteBuffer.begin(), vByteBuffer.end(), target.begin(), target.end());
    
    std::vector<uint8_t> vNTLMBuffer;
    
    if (it != vByteBuffer.cend())
    {
        vNTLMBuffer.assign(it, vByteBuffer.end());
    }
    this->serverMsg.deserialize(vNTLMBuffer);
    

}

bool SMB2SessionSetupAuth::generatePayload(std::vector<uint8_t> NTLMv2Hash, std::vector<uint8_t> RandomSessionKey)
{
    std::vector<uint8_t> vUsername;
    std::vector<uint8_t> vPassword;
    AttributeMap avPairs;
    std::vector<uint8_t> timeStamp;
    std::vector<uint8_t> blob;
    std::vector<uint8_t> Z6(6, 0x0);
    std::vector<uint8_t> Z4(4, 0x0);
    
    std::vector<uint8_t> sessionBaseKey;
    std::vector<uint8_t> EncryptedSessionKey;
    avPairs.deserialize(serverMsg.vTargetInfo);
    std::vector<uint8_t> clientNonce = genRandomHexVector(8);

    timeStamp = avPairs.getItem(AttributeMap::AvId::MsvAvTimestamp);

    // create blob
    blob.push_back(0x01);
    blob.push_back(0x01);
    blob = concat(blob, Z6);
    // TimeStamp
    blob = concat(blob, timeStamp);
    // clientNonce
    blob = concat(blob, clientNonce);
    // Z4
    blob = concat(blob, Z4);
    // targetInfo
    blob = concat(blob, avPairs.serialize());
    // padding Z4
    blob = concat(blob, Z4);
     
    std::vector<uint8_t> data = concat(serverMsg.ServerChall, blob);

    // calculate NtProof
    std::vector<uint8_t> NtProof; 
    BcryptHmacMd5Hash(data, NTLMv2Hash, NtProof);

    std::vector<uint8_t> ntChallengeResponse = concat(NtProof, blob);

    // Calculate SessionBaseKey
    // if using smb2 
    // don't use sessionbasekey
    if (RandomSessionKey.empty() == false)
    {
        BcryptHmacMd5Hash(NtProof, NTLMv2Hash, sessionBaseKey);
        EncryptedSessionKey = GenerateEncryptedSessionKey(RandomSessionKey, sessionBaseKey);
        clientMsg.NegotiateFlags = 0xe0888235;
    }
    

    // calculate LM response
    data = concat(serverMsg.ServerChall, clientNonce);
    std::vector<uint8_t> LMv2Response;
    BcryptHmacMd5Hash(data, NTLMv2Hash, LMv2Response);
    LMv2Response = concat(LMv2Response, clientNonce);
 
    // username
    size_t offset = 64;
    clientMsg.UserNameFields.len = clientMsg.UserNameFields.maxLen = username.size() * sizeof(wchar_t);
    clientMsg.UserNameFields.offset = offset;
    vUsername = wstringToBytes(username);
    offset += vUsername.size();
    // lm response
    clientMsg.LmChallengeResponseFields.maxLen = clientMsg.LmChallengeResponseFields.len = LMv2Response.size();
    clientMsg.LmChallengeResponseFields.offset = offset;
    offset += LMv2Response.size();
    // ntlmv2 response
    clientMsg.NtChallengeResponseFields.maxLen = clientMsg.NtChallengeResponseFields.len = ntChallengeResponse.size();
    clientMsg.NtChallengeResponseFields.offset = offset;
    offset += ntChallengeResponse.size();
    
    // domain 
    std::vector<uint8_t> vDomain = wstringToBytes(domain);
    clientMsg.DomainNameFields.len = clientMsg.DomainNameFields.maxLen = vDomain.size();
    clientMsg.DomainNameFields.offset = offset;
    offset += vDomain.size();
    //Workstation
    clientMsg.WorkstationFields.len = clientMsg.WorkstationFields.maxLen = 0;
    clientMsg.WorkstationFields.offset = offset + 4;
    
    // Encrypt session key
    clientMsg.EncryptedRandomSessionKeyFields.len = clientMsg.EncryptedRandomSessionKeyFields.maxLen = EncryptedSessionKey.size();
    clientMsg.EncryptedRandomSessionKeyFields.offset = offset;


    std::vector<uint8_t> result;
    result = clientMsg.serialize();
    result = concat(result, vUsername);
    result = concat(result, LMv2Response);
    result = concat(result, ntChallengeResponse);
    result = concat(result, vDomain);
    result = concat(result, EncryptedSessionKey);

    SPNEGO_NegTokenResp token;
    token.fields[L"ResponseToken"] = result;

    payload = token.getData();
    return true;

}