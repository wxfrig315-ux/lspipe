#include "SMB2ListTree.h"
#include "SMB2Logoff.h"
#include "SMB2CloseRequest.h"
#include "utils.h"
#include <iomanip>



bool SMB2ListTree(std::wstring treeConnect, std::wstring pattern, SmbClient& s_client)
{
	uint32_t status = 0;
	SMB2TreeConnect treeConnectPacket(treeConnect);
	treeConnectPacket.messageHandle(s_client.smbMessage);
	s_client.smbMessage = treeConnectPacket.buildSMB2TreeConnectPacket();

	if (s_client.sendSMBPacket() == false)
	{
		LogW(L"[-] Failed send treeConnectPacket" + std::to_wstring(GetLastError()) + L"\n");
		return false;
	}

	if (s_client.recvSMBPacket())
	{
		std::memcpy(&status, s_client.smbMessage.data() + 8, sizeof(NTSTATUS));
		if (status != 0)
		{
			LogW(L"[-] Failed SMB2TreeConnect " + std::to_wstring(status) + L"\n");
			return false;
		}
	}
	else
	{
		LogW(L"[-] Failed recv SMB2TreeConnect " + std::to_wstring(status) + L"\n");
		return false;
	}

	// SMB2 Create request packet
	SMB2CreateRequest createRequestPacket;
	createRequestPacket.messageHandle(s_client.smbMessage);
	s_client.smbMessage = createRequestPacket.buildSMB2CreateRequestPacket();


	if (s_client.sendSMBPacket() == false)
	{
		LogW(L"[-] Failed send SMB2CreateRequest" + std::to_wstring(GetLastError()) + L"\n");
		return false;
	}

	if (s_client.recvSMBPacket())
	{
		std::memcpy(&status, s_client.smbMessage.data() + 8, sizeof(NTSTATUS));
		if (status != 0)
		{
			LogW(L"[-] Failed SMB2CreateRequest: " + std::to_wstring(status) + L"\n");
			return false;
		}
	}
	else
	{
		LogW(L"[-] Failed recv SMB2CreateRequest packet: " + std::to_wstring(status) + L"\n");
		return false;
	}


	// SMB2 query directory packet
	SMB2QueryDirectory queryDirectoryPacket;
	queryDirectoryPacket.searchPattern = pattern;
	queryDirectoryPacket.messageHandle(s_client.smbMessage);


	SMB2QueryDirectoryResponse response;
	std::wstringstream wss;

	wss << std::endl;
	wss << std::left << std::setw(100) << L"Pipe Name" << std::setw(20) << L"Instances" << std::setw(13) << L"Max Instances\n";
	wss << std::left << std::setw(100) << std::wstring(10, L'-') << std::setw(20) << std::wstring(10, L'-') << std::setw(13) << std::wstring(20, L'-') << std::endl;

	while (true)
	{
		s_client.smbMessage = queryDirectoryPacket.buildSMB2QueryDirectoryPacket();
		if (s_client.sendSMBPacket() == false)
		{
			LogW(L"[-] Failed send SMB2Negotiate " + std::to_wstring(GetLastError()) + L"\n");
			return false;
		}
		
		if (s_client.recvSMBPacket())
		{

			std::memcpy(&status, s_client.smbMessage.data() + 8, sizeof(NTSTATUS));
			if (status != 0)
			{
				break;
			}
			response.deserialize(s_client.smbMessage);
			for (size_t i = 0; i < response.vFileInfo.size(); i++)
			{
				wss << std::left << std::setw(100) << response.vFileInfo[i].FileName;
				wss << std::left << std::setw(20) << response.vFileInfo[i].EndOfFile << L"\t";
				wss << std::right << std::setw(2) << static_cast<int32_t>(response.vFileInfo[i].AllocationSize) << std::endl;

			}
			queryDirectoryPacket.MessageId += 1;
		}
		else
		{
			LogW(L"[-] Failed recv SMB2QueryDirectory packet: " + std::to_wstring(status) + L"\n");
			break;
		}

	}
	LogW(wss.str());

	// Close request
	SMB2CloseRequest closeRequestPacket;
	closeRequestPacket.CreditCharge = 1;
	closeRequestPacket.ChannelSequence = 6;
	closeRequestPacket.Reserved = 0x80;
	closeRequestPacket.Command = 6;
	closeRequestPacket.CreditRequest = 0;
	closeRequestPacket.Flags = 0;
	closeRequestPacket.NextCommand = 0;
	closeRequestPacket.fileID = queryDirectoryPacket.FileId;

	std::memcpy(&closeRequestPacket.TreeId, s_client.smbMessage.data() + 36 , 4);
	std::memcpy(&closeRequestPacket.MessageId, s_client.smbMessage.data() + 24, 8);
	closeRequestPacket.MessageId++;

	std::memcpy(&closeRequestPacket.SessionId,
		s_client.smbMessage.data() + 40,
		sizeof(uint64_t));


	s_client.smbMessage = closeRequestPacket.buildSMB2CloseRequestPacket();

	if (s_client.sendSMBPacket() == false)
	{
		LogW(L"[-] Failed send closeRequestPacket" + std::to_wstring(GetLastError()) + L"\n");
		return false;
	}

	if (s_client.recvSMBPacket())
	{
		std::memcpy(&status, s_client.recv_buf.data() + 8, sizeof(NTSTATUS));
		if (status != 0)
		{
			LogW(L"[-] Failed CloseRequestPacket " + std::to_wstring(status) + L"\n");
			return false;
		}
	}
	else
	{
		LogW(L"[-] Failed recv CloseRequestPacket packet response " + std::to_wstring(GetLastError()) + L"\n");
		return false;
	}




	// Logoff request
	SMB2SessionLogoffRequest logOffRequestPacket;
	logOffRequestPacket.CreditCharge = 1;
	logOffRequestPacket.Command = 2;
	logOffRequestPacket.ChannelSequence = 0;
	logOffRequestPacket.Reserved = 0;
	logOffRequestPacket.CreditRequest = 0;
	logOffRequestPacket.Flags = 0;


	std::memcpy(&logOffRequestPacket.TreeId, s_client.smbMessage.data() + 36 , 4);
	std::memcpy(&logOffRequestPacket.MessageId, s_client.smbMessage.data() + 24, 8);
	logOffRequestPacket.MessageId++;

	std::memcpy(&logOffRequestPacket.SessionId,
		s_client.recv_buf.data() + 40,
		sizeof(uint64_t));
	


	s_client.smbMessage = logOffRequestPacket.buildSMB2SessionLogoffRequest();

	if (s_client.sendSMBPacket() == false)
	{
		LogW(L"[-] Failed send logOffRequestPacket" + std::to_wstring(GetLastError()) + L"\n");
		return false;
	}


	if (s_client.recvSMBPacket())
	{

		std::memcpy(&status, s_client.smbMessage.data() + 8, sizeof(NTSTATUS));
		if (status != 0)
		{
			LogW(L"[-] Failed logOffRequestPacket " + std::to_wstring(status) + L"\n");
			return false;
		}
	}
	else
	{
		LogW(L"[-] Failed recv logOffRequestPacket response " + std::to_wstring(GetLastError()) + L"\n");
		return false;
	}


	return true;
}
