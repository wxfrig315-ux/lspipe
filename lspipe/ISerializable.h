#pragma once

#include<vector>
#include<cstdint>

class ISerializable
{
public:
	virtual std::vector<uint8_t> serialize() {
		return std::vector<uint8_t>();
	};
	virtual bool deserialize(const std::vector<uint8_t>& vByteBuffer) {
		return false;
	};
	~ISerializable() = default;

private:

};

