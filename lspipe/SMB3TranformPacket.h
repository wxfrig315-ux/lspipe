#include<vector>
#include "utils.h"
#include "DirectTCPTransportHeader.h"
#include "IMessageHandler.h"
#include "SMBConnectionTable.h"
#include "BcryptAES.h"


class SMB3TranformPacket: public DirectTCPTransportHeader, public ISerializable, public IMessageHandler
{
public:
	uint32_t ProtocolId;
	std::vector<uint8_t> Signature;
	std::vector<uint8_t> Nonce;
	uint32_t OriginalMessageSize;
	uint16_t Reserved;
	union
	{
		uint16_t Flags;
		uint16_t EncryptionAlgorithm;
	};
	std::vector<uint8_t> SessionId;
	std::vector<uint8_t> originalData;
	std::vector<uint8_t> encryptedData;
	SMB3TranformPacket();
	~SMB3TranformPacket() = default;
	std::vector<uint8_t> serialize() override;
	bool deserialize(const std::vector<uint8_t>& vByteBuffer) override;
	void messageHandle(const std::vector<uint8_t>& vByteBuffer) override;
	std::vector<uint8_t> buildSMB3TranformHeader();

	bool encryptMessage(std::vector<uint8_t> EncryptionKey);
	bool decryptMessage(std::vector<uint8_t> DecryptionKey);

private:

};

