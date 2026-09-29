#include "SMB2Header.h"


SMB2Header::SMB2Header(): ProtocolId(0x424d53fe), StructureSize(64), Status(0), Command(0), MessageId(0), SessionId(0), TreeId(0),
CreditRequest(0), Flags(0), NextCommand(0), Reserved2(0), CreditCharge(0)
{
    this->Signature.assign(16, 0);
}


std::vector<uint8_t> SMB2Header::serialize() 
{
    std::vector<uint8_t> result;
    appendLE(result, this->ProtocolId );
    appendLE(result, this->StructureSize );
    appendLE(result, this->CreditCharge );
    appendLE(result, this->Reserved );
    appendLE(result, this->Command );
    appendLE(result, this->CreditRequest);
    appendLE(result, this->Flags);
    appendLE(result, this->NextCommand);
    appendLE(result, this->MessageId);
    appendLE(result, this->Reserved2);
    appendLE(result, this->TreeId);
    appendLE(result, this->SessionId);

    result = concat(result, Signature);
    return result;
}

bool SMB2Header::deserialize(const std::vector<uint8_t>& vByteBuffer)
{
    if (vByteBuffer.size() < 64)
    {
        return false;
    }

    std::memcpy(&Command, vByteBuffer.data() + 12, sizeof(Command));
    std::memcpy(&Flags, vByteBuffer.data() + 16, sizeof(Flags));
    std::memcpy(&MessageId, vByteBuffer.data() + 24, sizeof(MessageId));
    std::memcpy(&SessionId, vByteBuffer.data() + 40, sizeof(SessionId));
    std::memcpy(&TreeId, vByteBuffer.data() + 36, sizeof(TreeId));
    std::memcpy(&Status, vByteBuffer.data() + 8, sizeof(Status));
    
    Signature.assign(vByteBuffer.begin() + 48, vByteBuffer.begin() + 48 + 16);
    
    return true;
}

std::vector<uint8_t> SMB2Header::parseSMB2Header(std::vector<uint8_t> vByteBuffer)
{
    std::vector<uint8_t> remainBuffer;
    this->deserialize(vByteBuffer);

    remainBuffer.assign(
    vByteBuffer.begin() + 64,
        vByteBuffer.end()
    );

    return remainBuffer;
}

