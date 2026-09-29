#include "SMB2TreeConnect.h"

SMB2TreeConnect::SMB2TreeConnect(std::wstring wsPath):StructSize(9), Flag(0), Path(wsPath)
{
}

SMB2TreeConnect::~SMB2TreeConnect()
{
}

std::vector<uint8_t> SMB2TreeConnect::serialize()
{
	//	// SMB header = 64
	//	// size of TreeConnect =  8
	//
	std::vector<uint8_t> result;
	PathOffset = 64 + 8; // SMB header size + size SMB tree connect
	std::vector<uint8_t> tmp;
	tmp = wstringToBytes(this->Path);

	Flag = 0x0;
	PathLength = tmp.size();

	appendLE(result, StructSize);
	appendLE(result, Flag);
	appendLE(result, PathOffset);
	appendLE(result, PathLength);
	result = concat(result, tmp);
	
	return result;
}

void SMB2TreeConnect::messageHandle(const std::vector<uint8_t>& vByteBuffer)
{
	SMB2Header::deserialize(vByteBuffer);
	SMB2Header::Command = 3;
	SMB2Header::MessageId += 1;
	SMB2Header::Flags = 0;
	SMB2Header::CreditRequest = 127;
	SMB2Header::CreditCharge = 0;
	SMB2Header::Signature.assign(16, 0x0);
}

std::vector<uint8_t> SMB2TreeConnect::buildSMB2TreeConnectPacket()
{ 
	std::vector<uint8_t> result = SMB2TreeConnect::serialize();
	result = concat(SMB2Header::serialize(), result);
	
	return result;
}
