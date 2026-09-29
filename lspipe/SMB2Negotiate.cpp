#include "SMB2Negotiate.h"


SMB2Negotiate::SMB2Negotiate():StructSize(36),DialectCount(3), SecurityMode(1), Reserved(0), Capabilities(0x40), Reserved2(0)
{
	ClientGuid = generateClientGuid();
}

std::vector<uint8_t> SMB2Negotiate::serialize()
{

	this->Command = 0;
	this->Flags = 0;
	this->MessageId = 0;
	this->SecurityMode = 0x1;

	std::vector<uint16_t> Dialects;
	std::vector<uint8_t> data;
	Dialects.resize(DialectCount);
	Dialects[0] = 0x0202;
	Dialects[1] = 0x0210;
	Dialects[2] = 0x0300;
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
	data.insert(data.end(),tmp.begin(), tmp.end());

	// Reserved2 (8 bytes)
	appendLE(data, Reserved2);
	this->CreditCharge = calcCreditCharge(64 + 4 + data.size());
	// Dialects (2 bytes each)
	for (uint16_t dialect : Dialects)
	{
		appendLE(data, dialect);
	}

	return data;
}

std::vector<uint8_t> SMB2Negotiate::serializeGuid(const GUID& g)
{
	std::vector<uint8_t> result;

	result.push_back(g.Data1 & 0xFF);
	result.push_back((g.Data1 >> 8) & 0xFF);
	result.push_back((g.Data1 >> 16) & 0xFF);
	result.push_back((g.Data1 >> 24) & 0xFF);

	result.push_back(g.Data2 & 0xFF);
	result.push_back((g.Data2 >> 8) & 0xFF);

	result.push_back(g.Data3 & 0xFF);
	result.push_back((g.Data3 >> 8) & 0xFF);

	result.insert(result.end(), std::begin(g.Data4), std::end(g.Data4));

	return result;
}

std::vector<uint8_t> SMB2Negotiate::buildSMB2NegotiatePacket()
{
	std::vector<uint8_t> result = SMB2Negotiate::serialize();
	/*DirectTCPTransportHeader::setLength(result.size() + 64);*/
	result = concat(SMB2Header::serialize(), result);

	return result;
}

