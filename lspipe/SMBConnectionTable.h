#pragma once
#include <vector>
#include <cstdint>
#include"utils.h"
#include "BcryptSHA512.h"

#ifndef KDF_LABEL
#define KDF_LABEL             0x0
#endif

#ifndef KDF_CONTEXT
#define KDF_CONTEXT           0x1
#endif

#ifndef KDF_TARGET_LENGTH
#define KDF_TARGET_LENGTH     0x2
#endif

#ifndef BCRYPTBUFFER_VERSION
#define BCRYPTBUFFER_VERSION  0
#endif

class ConnectionTable
{
public:
	std::vector<byte> SMBSigningKey{ 0x53, 0x4D, 0x42, 0x53, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67, 0x4B, 0x65, 0x79, 0x00 };
	
	std::vector<byte> SMBC2SCipherKey{ 0x53, 0x4D, 0x42, 0x43, 0x32, 0x53, 0x43, 0x69, 0x70, 0x68, 0x65, 0x72, 0x4B, 0x65, 0x79, 0x00 };
	
	std::vector<uint8_t> SMBS2CCipherKey = { 0x53, 0x4D, 0x42, 0x53, 0x32 , 0x43,  0x43, 0x69, 0x70, 0x68, 0x65, 0x72, 0x4B, 0x65, 0x79, 0x00 };

	std::vector<byte> SMBAppKey = { 0x53, 0x4D, 0x42, 0x41, 0x70, 0x70, 0x4B, 0x65, 0x79, 0x00 };

	std::vector<uint8_t> encryptionKey;
	std::vector<uint8_t> keyExchange;
	std::vector<uint8_t> decryptionKey;
	std::vector<uint8_t> signingKey;
	std::vector<uint8_t> applicationKey;
	std::vector<uint8_t> RandomSessionKey;
	std::vector<uint8_t> SessionId;
	uint64_t MessageId = 0;
	uint32_t treeId;
	std::vector<uint8_t> FileId;
	std::vector<uint8_t> Salt;
	std::vector<byte> preHashAuth;

	ConnectionTable();
	~ConnectionTable() = default;
	std::vector<uint8_t> signPacket(std::vector<uint8_t> packetBuffer);
	void UpdateConnectionPreAuthHash(std::vector<byte> vByteBuffer);
	bool DeriveKeyCounterMode( const std::vector<uint8_t>& label, const std::vector<uint8_t>& context, std::vector<uint8_t>& derivedKey, DWORD derivedKeyLengthBits = 128);
private:

};
