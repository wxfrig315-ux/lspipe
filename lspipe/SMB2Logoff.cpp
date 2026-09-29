#include "SMB2Logoff.h"

SMB2SessionLogoffRequest::SMB2SessionLogoffRequest(): StructSize(4), Reserved(0)
{
}

std::vector<uint8_t> SMB2SessionLogoffRequest::serialize()
{
	std::vector<uint8_t> result;

	appendLE(result, StructSize);
	appendLE(result,Reserved);

	return result;
}

std::vector<uint8_t> SMB2SessionLogoffRequest::buildSMB2SessionLogoffRequest()
{
	std::vector<uint8_t> result;
	result = SMB2SessionLogoffRequest::serialize();
	result = concat(SMB2Header::serialize(), result);

	return result;
}
