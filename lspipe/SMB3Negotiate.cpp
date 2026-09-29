#include "SMB3Negotiate.h"


SMB3Negotiate::SMB3Negotiate()
{
	// salt use for sha512
	std::vector<uint8_t> Salt = genRandomHexVector(32);
	this->preAuth.ContextType = 0x01;
	this->preAuth.DataLength = 38;
	this->preAuth.Reserved = 0;
	appendLE(preAuth.Data, uint16_t(0x01));//HashAlgorithmCount: 1
	appendLE(preAuth.Data, uint16_t(32));//SaltLength: 32
	appendLE(preAuth.Data, uint16_t(0x1));//HashAlgorithm: SHA-512 (0x0001)
	preAuth.Data = concat(preAuth.Data, Salt);// salt random 32byte


	this->encryption.ContextType = 0x2;
	encryption.DataLength = 4;
	encryption.Reserved = 0;
	appendLE(encryption.Data, uint16_t(1));// Cipher count
	appendLE(encryption.Data, uint16_t(1)); // Cipher ID

}

std::vector<uint8_t> SMB3Negotiate::serialize()
{
	// change smb2 header field

	this->Command = 0;
	this->Flags = 0;
	this->MessageId = 0;
	this->SecurityMode = 0x1;

	this->NegotiateContextOffset = 0x68;
	this->NegotiateContextCount = 2;

	std::vector<uint8_t> result;
	std::vector<uint16_t> Dialects;
	std::vector<uint8_t> data;
	Dialects.resize(1);
	Dialects[0] = 0x311;
	// Ensure DialectCount matches actual number of dialects
	this->DialectCount = static_cast<uint16_t>(Dialects.size());

	// Header Fields
	appendLE(data, StructSize);       // 2 bytes
	appendLE(data, DialectCount);     // 2 bytes
	appendLE(data, SecurityMode);     // 2 bytes
	appendLE(data, Reserved);         // 2 bytes
	appendLE(data, Capabilities);     // 4 bytes

	// GUID (16 bytes)
	std::vector<uint8_t> tmp = serializeGuid(this->ClientGuid);
	data.insert(data.end(), tmp.begin(), tmp.end());

	// Reserved2 (8 bytes)
	appendLE(data, Reserved2);
	this->CreditCharge = calcCreditCharge(64 + 4 + data.size());
	// Dialects (2 bytes each)
	appendLE(data, Dialects[0]);
	//padding
	appendLE(data, uint8_t(0));
	appendLE(data, uint8_t(0));
	data = concat(data, preAuth.serialize());
	//padding
	appendLE(data, uint8_t(0));
	appendLE(data, uint8_t(0));
	data = concat(data, encryption.serialize());

	

	return data;
}

std::vector<uint8_t> SMB3Negotiate::buildSMB3NegotiatePacket()
{
	std::vector<uint8_t> result = SMB3Negotiate::serialize();

	result = concat(SMB2Header::serialize(), result);

	return result;
	
}

SMB2NegotiateContext::SMB2NegotiateContext()
{
}

std::vector<uint8_t> SMB2NegotiateContext::serialize()
{
	std::vector<uint8_t> result;
	appendLE(result, ContextType);
	appendLE(result, DataLength);
	appendLE(result, Reserved);
	result = concat(result, Data);

	return result;
}
