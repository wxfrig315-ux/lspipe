#pragma once
#include<vector>
#include"ISerializable.h"



class DirectTCPTransportHeader : public ISerializable
{
public:
	DirectTCPTransportHeader();
	~DirectTCPTransportHeader() = default;

	void setLength(uint32_t value);
	uint32_t getLength();

	std::vector<uint8_t> serialize()  override;
	bool deserialize(const std::vector<uint8_t>& vByteBuffer) override;

	uint8_t Zero = 0;
	std::vector<uint8_t> StreamProtocolLength;
};

