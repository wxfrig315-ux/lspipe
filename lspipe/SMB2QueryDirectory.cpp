#include "SMB2QueryDirectory.h"



SMB2QueryDirectory::SMB2QueryDirectory(): StructSize(0x21), 
FileInfomationClass(0x1) , Flags(0x0), FileIndex(0), 
OutputBufferLength(65535), FileNameOffset(0x60)
{
   
}

SMB2QueryDirectory::~SMB2QueryDirectory()
{
}

std::vector<uint8_t> SMB2QueryDirectory::serialize()
{
    std::vector<uint8_t> result;
    std::vector<uint8_t> tmp = wstringToBytes(searchPattern);
    FileNameLength = sizeof(wchar_t) * searchPattern.size();
    appendLE(result, this->StructSize);
    appendLE(result, this->FileInfomationClass);
    appendLE(result, this->Flags);
    appendLE(result, this->FileIndex);
    result = concat(result, FileId);
    appendLE(result, this->FileNameOffset);
    appendLE(result, this->FileNameLength);
    appendLE(result, this->OutputBufferLength);
    result = concat(result, tmp );

    return result;
}

void SMB2QueryDirectory::messageHandle(const std::vector<uint8_t>& vByteBuffer)
{
    SMB2Header::deserialize(vByteBuffer);
    SMB2Header::CreditCharge = 16;
    SMB2Header::Reserved = 0;
    SMB2Header::Command = 14;
    SMB2Header::CreditRequest = 16;
    SMB2Header::Flags = 0;
    SMB2Header::MessageId += 1;
    SMB2Header::NextCommand = 0;
    SMB2Header::CreditCharge = 0;

    this->FileId.assign(vByteBuffer.begin() + 64 + 64, vByteBuffer.begin()+ 64+ 64+ 16);

}


std::vector<uint8_t> SMB2QueryDirectory::buildSMB2QueryDirectoryPacket()
{
    std::vector<uint8_t> result = SMB2QueryDirectory::serialize();
    result = concat(SMB2Header::serialize(), result);

    return result;
}

