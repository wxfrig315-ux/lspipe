#include "SMB2Login.h"

bool SMB2Login(SmbClient &s_client, std::wstring username, std::wstring domain, std::wstring password, std::wstring NtHash)
{
	uint32_t status = 0;
	if (password.empty() && NtHash.empty())
	{
		LogW(L"Require only password or NTLM Hash\n");
		return false;
	}

	//dialect
	SMB2Negotiate negotiatePacket;
	s_client.smbMessage = negotiatePacket.buildSMB2NegotiatePacket();

	if (s_client.sendSMBPacket() == false)
	{
		LogW(L"[-] Failed send SMB2Negotiate" + std::to_wstring(GetLastError()) + L"\n");
		return false;
	}
	
	if (s_client.recvSMBPacket())
	{
		std::memcpy(&status, s_client.smbMessage.data()+ 8, sizeof(NTSTATUS));
		if (status != 0)
		{
			LogW(L"[-] Failed recv SMB2Negotiate " + std::to_wstring(status) + L"\n");
			return false;
		}
	}
	else
	{
		LogW(L"[-] Failed recv SMB2Negotiate packet: " + std::to_wstring(status) + L"\n");
		return false;
	}

	
	// RequestSessionSetup
	SMB2SessionSetupRequest requestNTLMPacket;
	requestNTLMPacket.messageHandle(s_client.smbMessage);
	requestNTLMPacket.generatePayload();
	requestNTLMPacket.msg.NegotiateFlags = 0xa0880205;
	s_client.smbMessage = requestNTLMPacket.buildSMB2SessionSetupRequestPacket();
	
	if (s_client.sendSMBPacket() == false)
	{
		LogW(L"[-] Failed send SMB2SessionSetupRequest" + std::to_wstring(GetLastError()) + L"\n");
		return false;
	}

	if (s_client.recvSMBPacket())
	{
		std::memcpy(&status, s_client.smbMessage.data() + 8, sizeof(NTSTATUS));
		if (status != 0xc0000016)
		{
			LogW(L"[-] Failed SMB2SessionSetupRequest " + std::to_wstring(status) + L"\n");
			return false;
		}
	}
	else
	{
		LogW(L"[-] Failed  recv SMB2SessionSetupRequest " + std::to_wstring(status) + L"\n");
		return false;
	}

	//Authen packet
	SMB2SessionSetupAuth setupAuthPacket;
	setupAuthPacket.username = username;
	setupAuthPacket.domain = domain;
	if (NtHash.empty() == false)
	{
		setupAuthPacket.ntHash = hexStringToBytes(NtHash);
	}
	if (password.empty() == false)
	{
		setupAuthPacket.password = password;
	}

	setupAuthPacket.messageHandle(s_client.smbMessage);
	std::vector<uint8_t> NTLMv2;
	NTOWFv2(username, password, domain, setupAuthPacket.ntHash, NTLMv2);
	setupAuthPacket.generatePayload(NTLMv2, std::vector<uint8_t>());
	s_client.smbMessage = setupAuthPacket.buildSMB2SessionSetupAuthPacket();
	
	if (s_client.sendSMBPacket() == false)
	{
		LogW(L"[-] Failed send setupAuthPacket" + std::to_wstring(GetLastError()) + L"\n");
		return false;
	}

	if (s_client.recvSMBPacket())
	{
		std::memcpy(&status, s_client.smbMessage.data()  + 8, sizeof(NTSTATUS));
		if (status != 0)
		{
			LogW(L"[-] Failed SMB2SessionSetupAuth " + std::to_wstring(status) + L"\n");
			return false;
		}
	}
	else
	{
		LogW(L"[-] Failed recv SMB2SessionSetupAuth " + std::to_wstring(status) + L"\n");
		return false;
	}
    return true;
}

