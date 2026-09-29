#include "SMB2CloseRequest.h"

std::vector<uint8_t> SMB2CloseRequest::serialize()
{
	std::vector<uint8_t> result;
	appendLE(result, StructSize);
	appendLE(result, Flags);
	appendLE(result, SMB2CloseRequest::Reserved);
	 
	result = concat(result, fileID);
	return result;

}

SMB2CloseRequest::SMB2CloseRequest():Flags(0), StructSize(0x18)
{
}

std::vector<uint8_t> SMB2CloseRequest::buildSMB2CloseRequestPacket()
{
	std::vector<uint8_t> result;
	result = SMB2CloseRequest::serialize();
	result = concat(SMB2Header::serialize(), result);

	return result;
}
