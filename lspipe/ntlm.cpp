#include "ntlm.h"

NTLMType1Message::NTLMType1Message(): Signature(0x005053534d4c544e), MessageType(1), NegotiateFlags(0xa0880205),Version(0)
{
	this->Domain.len = this->Domain.maxLen = this->Domain.offset = 0;
	this->WorkStation.len = this->WorkStation.maxLen = this->WorkStation.offset = 0;
}

std::vector<uint8_t> NTLMType1Message::serialize()
{
	std::vector<uint8_t> result;
	appendLE(result, Signature);
	appendLE(result, MessageType);
	appendLE(result, NegotiateFlags);
	//Append domain
	appendLE(result, Domain.len);
	appendLE(result, Domain.maxLen);
	appendLE(result, Domain.offset);
	//append workstation
	appendLE(result, WorkStation.len);
	appendLE(result, WorkStation.maxLen);
	appendLE(result, WorkStation.offset);

	if (Version != 0)
	{
		appendLE(result, Version);
	}

	if (Payload.empty() == false)
	{
		result = concat(result, Payload);
	}
	
	return result;
}

bool NTLMType1Message::deserialize(const std::vector<uint8_t>& vByteBuffer)
{
	size_t offset = 0;
	std::memcpy(&this->Signature, vByteBuffer.data() + offset, sizeof(this->Signature));
	offset += sizeof(this->Signature);

	std::memcpy(&this->MessageType, vByteBuffer.data() + offset, sizeof(this->MessageType));
	offset += sizeof(this->MessageType);

	std::memcpy(&this->NegotiateFlags, vByteBuffer.data() + offset, sizeof(this->NegotiateFlags));
	offset += sizeof(this->NegotiateFlags);

	std::memcpy(&this->Domain, vByteBuffer.data() + offset, sizeof(this->Domain));
	offset += sizeof(this->Domain);

	std::memcpy(&this->WorkStation, vByteBuffer.data() + offset, sizeof(this->WorkStation));
	offset += sizeof(this->WorkStation);

	if (offset + sizeof(this->Version) < vByteBuffer.size())
	{
		std::memcpy(&this->Version, vByteBuffer.data() + offset, sizeof(this->Version));
		offset += sizeof(this->Version);
	}
	if (offset  < vByteBuffer.size())
	{
		this->Payload.assign(vByteBuffer.begin() + offset, vByteBuffer.end());
	}

	return true;
}

NTLMType2Message::NTLMType2Message()
{
	this->ServerChall.assign(8, 0);
}

bool NTLMType2Message::deserialize(const std::vector<uint8_t>& vByteBuffer)
{
	size_t offset = 0;
	std::memcpy(&this->Signature, vByteBuffer.data() + offset, sizeof(this->Signature));
	offset += sizeof(this->Signature);
	std::memcpy(&this->MessageType, vByteBuffer.data() + offset, sizeof(this->MessageType));
	offset += sizeof(this->MessageType);
	std::memcpy(&this->TargetNameFields, vByteBuffer.data() + offset, sizeof(this->TargetNameFields));
	offset += sizeof(this->TargetNameFields);
	std::memcpy(&this->NegotiateFlags, vByteBuffer.data() + offset, sizeof(this->NegotiateFlags));
	offset += sizeof(this->NegotiateFlags);

	this->ServerChall.assign(vByteBuffer.begin() + offset, vByteBuffer.begin() + offset + 8);
	offset += ServerChall.size();

	std::memcpy(&this->Reserved, vByteBuffer.data() + offset, sizeof(this->Reserved));
	offset += sizeof(this->Reserved);

	std::memcpy(&this->TargetInfoFields, vByteBuffer.data() + offset, sizeof(this->TargetInfoFields));
	offset += sizeof(this->TargetInfoFields);
	
	std::memcpy(&this->Version, vByteBuffer.data() + offset, sizeof(this->Version));
	offset += sizeof(this->Version);


	this->vTargetInfo.assign(vByteBuffer.begin() + this->TargetInfoFields.offset,
		vByteBuffer.begin()+ +this->TargetInfoFields.offset + this->TargetInfoFields.len);

	this->vTargetName.assign(vByteBuffer.begin() + this->TargetNameFields.offset,
		vByteBuffer.begin()+ +this->TargetNameFields.offset + this->TargetNameFields.len);
	return true;
}


NTLMType3Message::NTLMType3Message(): Signature(0x005053534d4c544e), MessageType(3), NegotiateFlags(0xe0888235), Version(0)
{
	
}

std::vector<uint8_t> NTLMType3Message::serialize()
{
	std::vector<uint8_t> result;
	appendLE(result, this->Signature);
	appendLE(result, this->MessageType);
	
	appendLE(result, LmChallengeResponseFields.len);
	appendLE(result, LmChallengeResponseFields.maxLen);
	appendLE(result, LmChallengeResponseFields.offset);
	
	appendLE(result, NtChallengeResponseFields.len);
	appendLE(result, NtChallengeResponseFields.maxLen);
	appendLE(result, NtChallengeResponseFields.offset);

	appendLE(result, DomainNameFields.len);
	appendLE(result, DomainNameFields.maxLen);
	appendLE(result, DomainNameFields.offset);
	
	appendLE(result, UserNameFields.len);
	appendLE(result, UserNameFields.maxLen);
	appendLE(result, UserNameFields.offset);

	appendLE(result, WorkstationFields.len);
	appendLE(result, WorkstationFields.maxLen);
	appendLE(result, WorkstationFields.offset);

	appendLE(result, EncryptedRandomSessionKeyFields.len);
	appendLE(result, EncryptedRandomSessionKeyFields.maxLen);
	appendLE(result, EncryptedRandomSessionKeyFields.offset);

	appendLE(result, NegotiateFlags);

	if (Version != 0)
	{
		appendLE(result, Version);
	}
	if (MIC.empty() == false)
	{
		result = concat(result, MIC);
	}
	
	return concat(result, Payload);

}
