#include "SMB3TranformPacket.h"

SMB3TranformPacket::SMB3TranformPacket(): ProtocolId(0x424D53FD)
{
	Signature.resize(16);
	Nonce.resize(16);
	SessionId.resize(8);
	Reserved = 0;
	Flags = 1;

}

std::vector<uint8_t> SMB3TranformPacket::serialize()
{
	std::vector<uint8_t> result;
	OriginalMessageSize = encryptedData.size();

	appendLE(result, this->ProtocolId);
	result = concat(result, Signature);
	result = concat(result, Nonce);
	appendLE(result, OriginalMessageSize);
	appendLE(result, Reserved);
	appendLE(result, Flags);
	result = concat(result, SessionId);
	result = concat(result, encryptedData);

	return result;
}

bool SMB3TranformPacket::deserialize(const std::vector<uint8_t>& vByteBuffer)
{
	// only deserialize  
	// skip netbios first 4byte

	size_t offset = 0;

	if (vByteBuffer.size() < 52)
	{
		LogW(L"[-] Transform packet too small: " + std::to_wstring(vByteBuffer.size()) + L" bytes\n");
		return false;
	}

	std::memcpy(&this->ProtocolId, vByteBuffer.data(), sizeof(uint32_t));
	offset += sizeof(this->ProtocolId);

	Signature.assign(vByteBuffer.data() + offset, vByteBuffer.data() + offset + 16);
	offset += 16;

	Nonce.assign(vByteBuffer.begin() + offset, vByteBuffer.begin() + offset + 16);
	offset += 16;

	std::memcpy(&OriginalMessageSize, vByteBuffer.data() + offset, sizeof(OriginalMessageSize));
	offset += sizeof(OriginalMessageSize);

	std::memcpy(&Reserved, vByteBuffer.data() + offset, sizeof(Reserved));
	offset += sizeof(Reserved);

	std::memcpy(&Flags, vByteBuffer.data() + offset, sizeof(Flags));
	offset += sizeof(Flags);
	
	SessionId.assign(vByteBuffer.begin() + offset, vByteBuffer.begin() + offset + 8);
	offset += 8;

	if (OriginalMessageSize > (vByteBuffer.size() - offset))
	{
		LogW(L"[-] Transform packet truncated: need " + std::to_wstring(offset + OriginalMessageSize)
			+ L" bytes, got " + std::to_wstring(vByteBuffer.size()) + L"\n");
		return false;
	}

	encryptedData.assign(vByteBuffer.begin() + offset, vByteBuffer.begin() + offset + OriginalMessageSize);
	return true;
}

void SMB3TranformPacket::messageHandle(const std::vector<uint8_t>& vByteBuffer)
{
	SMB3TranformPacket::deserialize({ vByteBuffer.begin() +4, vByteBuffer.end()});
}

std::vector<uint8_t> SMB3TranformPacket::buildSMB3TranformHeader()
{
	std::vector<uint8_t> result = SMB3TranformPacket::serialize();
	return result;
}

bool SMB3TranformPacket::encryptMessage(std::vector<uint8_t> EncryptionKey)
{
	std::vector<uint8_t> z5(5, 0);
	Nonce = genRandomHexVector(11);
	std::vector<uint8_t> slicedNonce = Nonce;
	Nonce = concat(Nonce, z5);

	std::vector<uint8_t> aad;
	aad = concat(aad, Nonce);
	appendLE(aad, OriginalMessageSize);// false missing error
	appendLE(aad, Reserved);
	appendLE(aad, Flags);
	aad = concat(aad, SessionId);

	AESCCM_Encrypt(
		EncryptionKey,
		slicedNonce, 
		aad, 
		originalData,
		encryptedData,
		this->Signature);

	return true;
}

bool SMB3TranformPacket::decryptMessage(std::vector<uint8_t> DecryptionKey)
{
	if (Nonce.size() < 11 || encryptedData.empty())
	{
		LogW(L"[-] Transform packet invalid for decryption\n");
		return false;
	}

	std::vector<uint8_t> slicedNonce(Nonce.begin(), Nonce.begin() + 11);
	std::vector<uint8_t> aad;
	aad = concat(aad, Nonce);
	appendLE(aad, OriginalMessageSize);
	appendLE(aad, Reserved);
	appendLE(aad, Flags);
	aad = concat(aad, SessionId);
	
	NTSTATUS status = AESCCM_Decrypt(DecryptionKey, 
		slicedNonce,
		aad,
		encryptedData,
		Signature,
		originalData);
	
	if (!NT_SUCCESS(status))
	{
		LogW(L"[-] Transform decryption failed: NTSTATUS 0x" + std::to_wstring(static_cast<unsigned long>(status)) + L"\n");
		return false;
	}
	return true;
}
