#include "SMB3.h"

SMB3::SMB3()
{
}

bool SMB3::SMB3Login(SmbClient& s_client, std::wstring username, std::wstring domain, std::wstring password, std::wstring NtHash)
{
	SMB3Negotiate negMessage;
	NTSTATUS status = 0;
	// Dialect SMB3.1.1
	// Preauth hash SHA512
	s_client.smbMessage = negMessage.buildSMB3NegotiatePacket();
	this->SessionInfo.UpdateConnectionPreAuthHash({ s_client.smbMessage.begin(), s_client.smbMessage.end() });

	if (s_client.sendSMBPacket() == false)
	{
		LogW(L"[-] Failed send SMB3Negotiate" + std::to_wstring(GetLastError()) + L"\n");
		return false;
	}
	
	if (s_client.recvSMBPacket())
	{
		std::memcpy(&status, s_client.recv_buf.data() + 8, sizeof(NTSTATUS));
		if (status != 0)
		{
			LogW(L"[-] Failed SMB3Negotiate: " + std::to_wstring(status) + L"\n");
			return false;
		}
	}
	else
	{
		LogW(L"[-] Failed recv SMB3Negotiate packet response " + std::to_wstring(GetLastError()) +L"\n");
		return false;
	}
	
	LogW(L"[+] Negotiate success\n" );


	this->SessionInfo.UpdateConnectionPreAuthHash({ s_client.smbMessage.begin(), s_client.smbMessage.end() });

	// Session setup request 
	SMB2SessionSetupRequest requestNTLMPacket;
	requestNTLMPacket.messageHandle(s_client.recv_buf);
	requestNTLMPacket.msg.NegotiateFlags = 0xe0888235;
	requestNTLMPacket.generatePayload();
	s_client.smbMessage = requestNTLMPacket.buildSMB2SessionSetupRequestPacket();

	this->SessionInfo.UpdateConnectionPreAuthHash({ s_client.smbMessage.begin(), s_client.smbMessage.end() });

	if (s_client.sendSMBPacket() == false)
	{
		LogW(L"[-] Failed send SMB2SessionSetupRequest" + std::to_wstring(GetLastError()) + L"\n");
		return false;
	}
	
	if (s_client.recvSMBPacket())
	{
		std::memcpy(&status, s_client.recv_buf.data() + 8, sizeof(NTSTATUS));
		if (status != 0xc0000016)
		{
			LogW(L"[-] Failed SessionSetupRequest: " + std::to_wstring(status) + L"\n");
			return false;
		}
	}
	else
	{
		LogW(L"[-] Failed recv SMB2SessionSetupRequest packet response " + std::to_wstring(GetLastError()) + L"\n");
		return false;
	}
	

	this->SessionInfo.UpdateConnectionPreAuthHash({ s_client.smbMessage.begin(), s_client.smbMessage.end() });


	// Authentication packet
	// NTLMSSP
	std::vector<uint8_t> responseKeyNT;
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

	setupAuthPacket.messageHandle(s_client.recv_buf);
	NTOWFv2(username, password, domain, setupAuthPacket.ntHash, responseKeyNT);
	
	setupAuthPacket.generatePayload(responseKeyNT, this->SessionInfo.RandomSessionKey);
	s_client.smbMessage = setupAuthPacket.buildSMB2SessionSetupAuthPacket();
	this->SessionInfo.UpdateConnectionPreAuthHash({ s_client.smbMessage.begin(), s_client.smbMessage.end() });
	
	if (s_client.sendSMBPacket() == false)
	{
		LogW(L"[-] Failed send setupAuthPacket" + std::to_wstring(GetLastError()) + L"\n");
		return false;
	}
	
	if (s_client.recvSMBPacket())
	{
		std::memcpy(&status, s_client.recv_buf.data() + 8, sizeof(NTSTATUS));
		if (status != 0)
		{
			LogW(L"[-] Failed SMBAuth: " + std::to_wstring(status) + L"\n");
			return false;
		}
	}
	else
	{
		LogW(L"[-] Failed recv SMBAuth packet response " + std::to_wstring(GetLastError()) + L"\n");
		return false;
	}
	

	// get session ID 
	// get message ID 
	this->SessionInfo.SessionId.assign(
		s_client.recv_buf.begin()  + 40, s_client.recv_buf.begin() + 48);

	std::memcpy(&this->SessionInfo.MessageId, s_client.recv_buf.data() + 24, sizeof(uint64_t));


	// Encryption Key
	this->SessionInfo.DeriveKeyCounterMode(
		this->SessionInfo.SMBC2SCipherKey,
		this->SessionInfo.preHashAuth,
		this->SessionInfo.encryptionKey,
		128
	);

	// Decryption Key
	this->SessionInfo.DeriveKeyCounterMode(
		this->SessionInfo.SMBS2CCipherKey,
		this->SessionInfo.preHashAuth,
		this->SessionInfo.decryptionKey,
		128
	);
	
	// SignKey
	this->SessionInfo.DeriveKeyCounterMode(
		this->SessionInfo.SMBSigningKey,
		this->SessionInfo.preHashAuth,
		this->SessionInfo.signingKey,
		128
	);

	return true;
}

bool SMB3::SMB3ListTree(SmbClient& s_client, std::wstring treeConnect, std::wstring pattern)
{

	// build tree connect packet
	SMB3TranformPacket outgoingTransformPacket , incomingTransformPacket;
	SMB2TreeConnect treeConnectPacket(treeConnect);
	std::vector<uint8_t> msg;
	NTSTATUS status = 0;

	treeConnectPacket.Command = 3;
	treeConnectPacket.MessageId = ++this->SessionInfo.MessageId;
	treeConnectPacket.Flags = 0;
	treeConnectPacket.CreditRequest = 127;
	treeConnectPacket.CreditCharge = 1;
	treeConnectPacket.ChannelSequence = 0;
	treeConnectPacket.Reserved = 0;
	treeConnectPacket.Reserved2 = 0;
	treeConnectPacket.NextCommand = 0;
	

	std::memcpy(&treeConnectPacket.SessionId, 
		SessionInfo.SessionId.data(), 
		SessionInfo.SessionId.size());
	

	outgoingTransformPacket.SessionId = SessionInfo.SessionId;
	msg = treeConnectPacket.buildSMB2TreeConnectPacket();
	treeConnectPacket.Signature = SessionInfo.signPacket(msg);
	
	outgoingTransformPacket.originalData = msg;
	outgoingTransformPacket.OriginalMessageSize = msg.size();
	outgoingTransformPacket.encryptMessage(this->SessionInfo.encryptionKey);

	s_client.smbMessage = outgoingTransformPacket.buildSMB3TranformHeader();

	if (s_client.sendSMBPacket() == false)
	{
		LogW(L"[-] Failed send treeConnectPacket" + std::to_wstring(GetLastError()) + L"\n");
		return false;
	}
	
	if (s_client.recvSMBPacket())
	{
		if (incomingTransformPacket.deserialize(s_client.smbMessage) == false ||
			incomingTransformPacket.decryptMessage(this->SessionInfo.decryptionKey) == false)
		{
			LogW(L"[-] Failed decrypt TreeConnect response\n");
			return false;
		}

		std::memcpy(&status, incomingTransformPacket.originalData.data() + 8, sizeof(NTSTATUS));
		if (status != 0)
		{
			LogW(L"[-] Failed TreeConnect " + std::to_wstring(status) + L"\n");
			return false;
		}
	}
	else
	{
		LogW(L"[-] Failed recv SMB2TreeConnect packet response " + std::to_wstring(GetLastError()) + L"\n");
		return false;
	}


	// Processing receive packet
	// receceive Tree ID
	std::memcpy(&SessionInfo.treeId,
		incomingTransformPacket.originalData.data() + 36,
		sizeof(SessionInfo.treeId));

	// build SMB2 Create request packet
	SMB2CreateRequest createRequestPacket;

	createRequestPacket.MessageId = ++this->SessionInfo.MessageId;
	createRequestPacket.Command = 5;
	createRequestPacket.CreditRequest = 127;
	createRequestPacket.Flags = 0;
	createRequestPacket.Reserved2 = 0;
	createRequestPacket.TreeId = SessionInfo.treeId;

	std::memcpy(&createRequestPacket.SessionId,
		SessionInfo.SessionId.data(),
		SessionInfo.SessionId.size());

	outgoingTransformPacket.SessionId = SessionInfo.SessionId;

	msg = createRequestPacket.buildSMB2CreateRequestPacket();
	
	// build outgoingtransform packet
	outgoingTransformPacket.originalData = msg;
	outgoingTransformPacket.OriginalMessageSize = msg.size();
	outgoingTransformPacket.encryptMessage(this->SessionInfo.encryptionKey);

	s_client.smbMessage = outgoingTransformPacket.buildSMB3TranformHeader();
	
	if (s_client.sendSMBPacket() == false)
	{
		LogW(L"[-] Failed send createRequestPacket" + std::to_wstring(GetLastError()) + L"\n");
		return false;
	}
	
	
	if (s_client.recvSMBPacket())
	{
		if (incomingTransformPacket.deserialize(s_client.smbMessage) == false ||
			incomingTransformPacket.decryptMessage(this->SessionInfo.decryptionKey) == false)
		{
			LogW(L"[-] Failed decrypt SMB3CreateRequest response\n");
			return false;
		}
		std::memcpy(&status, incomingTransformPacket.originalData.data() + 8, sizeof(NTSTATUS));
		if (status != 0)
		{
			LogW(L"[-] Failed SMB3CreateRequest " + std::to_wstring(status) + L"\n");
			return false;
		}
	}
	else
	{
		LogW(L"[-] Failed recv SMB3CreateRequest packet response " + std::to_wstring(GetLastError()) + L"\n");
		return false;
	}

	
	SessionInfo.FileId.assign(incomingTransformPacket.originalData.begin() + 64 + 64,
		incomingTransformPacket.originalData.begin() + 64 + 64 + 16);

	// SMB2 query directory packet
	SMB2QueryDirectory queryDirectoryPacket;
	queryDirectoryPacket.searchPattern = pattern;
	queryDirectoryPacket.CreditCharge = 1;
	queryDirectoryPacket.Reserved = 0;
	queryDirectoryPacket.Command = 14;
	queryDirectoryPacket.CreditRequest = 16;
	queryDirectoryPacket.Flags = 0;
	queryDirectoryPacket.NextCommand = 0;
	queryDirectoryPacket.TreeId = SessionInfo.treeId;
	queryDirectoryPacket.FileId = SessionInfo.FileId;
	
	SMB2QueryDirectoryResponse response;
	std::wstringstream wss;

	wss << std::endl;
	wss << std::left << std::setw(100) << L"Pipe Name"
		<< std::setw(20) << L"Instances"
		<< std::setw(20) << L"Max Instances" << std::endl;

	wss << std::left << std::setw(100) << std::wstring(10, L'-')
		<< std::setw(20) << std::wstring(10, L'-')
		<< std::setw(20) << std::wstring(10, L'-')
		<< std::endl;
	while (true)
	{
		std::memcpy(&queryDirectoryPacket.SessionId,
			SessionInfo.SessionId.data(),
			SessionInfo.SessionId.size());

		queryDirectoryPacket.MessageId = ++SessionInfo.MessageId;
		outgoingTransformPacket.SessionId = SessionInfo.SessionId;

		msg = queryDirectoryPacket.buildSMB2QueryDirectoryPacket();

		outgoingTransformPacket.originalData = msg;
		outgoingTransformPacket.OriginalMessageSize = msg.size();
		outgoingTransformPacket.encryptMessage(this->SessionInfo.encryptionKey);

		s_client.smbMessage = outgoingTransformPacket.buildSMB3TranformHeader();


		if (s_client.sendSMBPacket() == false)
		{
			LogW(L"[-] Failed send queryDirectoryPacket" + std::to_wstring(GetLastError()) + L"\n");
			return false;
		}

		if (s_client.recvSMBPacket())
		{
			std::vector<uint8_t> Buffer;
			if (incomingTransformPacket.deserialize(s_client.recv_buf) == false ||
				incomingTransformPacket.decryptMessage(this->SessionInfo.decryptionKey) == false)
			{
				LogW(L"[-] Failed decrypt queryDirectoryPacket response\n");
				return false;
			}

			// get status SMB header
			std::memcpy(&status, incomingTransformPacket.originalData.data() + 8, sizeof(status));

			if(status == 0)
			{
				std::memcpy(&response.OutputBufferOffset, incomingTransformPacket.originalData.data() + 64 + sizeof(SMB2CreateRequest::StructSize), sizeof(response.OutputBufferOffset));
				std::memcpy(&response.OutputBufferLength, incomingTransformPacket.originalData.data() + 64 + sizeof(SMB2CreateRequest::StructSize) + sizeof(response.OutputBufferOffset), sizeof(response.OutputBufferLength));

				Buffer.assign(incomingTransformPacket.originalData.begin() + sizeof(SMB2CreateRequest::StructSize) + sizeof(SMB2QueryDirectoryResponse::OutputBufferOffset) + sizeof(SMB2QueryDirectory::OutputBufferLength) + 64,
					incomingTransformPacket.originalData.end());
				response.vFileInfo = response.parseSMB2QueryDirectoryResponse(Buffer);

				for (size_t i = 0; i < response.vFileInfo.size(); i++)
				{
					wss << std::left << std::setw(100) << response.vFileInfo[i].FileName;
					wss << std::left << std::setw(20) << response.vFileInfo[i].EndOfFile << L"\t";
					wss << std::right << std::setw(2) << static_cast<int32_t>(response.vFileInfo[i].AllocationSize) << std::endl;

				}
			}
			else
			{
				break;
			}
		}
		else
		{
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
	closeRequestPacket.NextCommand  = 0;
	closeRequestPacket.MessageId = ++SessionInfo.MessageId;
	closeRequestPacket.TreeId = SessionInfo.treeId;
	closeRequestPacket.fileID = SessionInfo.FileId;

	std::memcpy(&closeRequestPacket.SessionId,
		SessionInfo.SessionId.data(),
		SessionInfo.SessionId.size());
	

	msg = closeRequestPacket.buildSMB2CloseRequestPacket();
	outgoingTransformPacket.originalData = msg;
	outgoingTransformPacket.OriginalMessageSize = msg.size();
	outgoingTransformPacket.encryptMessage(this->SessionInfo.encryptionKey);

	s_client.smbMessage = outgoingTransformPacket.buildSMB3TranformHeader();
	
	if (s_client.sendSMBPacket() == false)
	{
		LogW(L"[-] Failed send closeRequestPacket" + std::to_wstring(GetLastError()) + L"\n");
		return false;
	}

	if (s_client.recvSMBPacket())
	{
		if (incomingTransformPacket.deserialize(s_client.smbMessage) == false ||
			incomingTransformPacket.decryptMessage(this->SessionInfo.decryptionKey) == false)
		{
			LogW(L"[-] Failed decrypt CloseRequestPacket response\n");
			return false;
		}

		std::memcpy(&status, incomingTransformPacket.originalData.data() + 8, sizeof(NTSTATUS));
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
	logOffRequestPacket.MessageId = ++SessionInfo.MessageId;
	logOffRequestPacket.TreeId = SessionInfo.treeId;

	std::memcpy(&logOffRequestPacket.SessionId,
		SessionInfo.SessionId.data(),
		SessionInfo.SessionId.size());
	msg = logOffRequestPacket.buildSMB2SessionLogoffRequest();

	outgoingTransformPacket.originalData = msg;
	outgoingTransformPacket.OriginalMessageSize = msg.size();
	outgoingTransformPacket.encryptMessage(this->SessionInfo.encryptionKey);

	s_client.smbMessage = outgoingTransformPacket.buildSMB3TranformHeader();

	if (s_client.sendSMBPacket() == false)
	{
		LogW(L"[-] Failed send logOffRequestPacket" + std::to_wstring(GetLastError()) + L"\n");
		return false;
	}
	
	
	if (s_client.recvSMBPacket())
	{
		if (incomingTransformPacket.deserialize(s_client.smbMessage) == false ||
			incomingTransformPacket.decryptMessage(this->SessionInfo.decryptionKey) == false)
		{
			LogW(L"[-] Failed decrypt logOffRequestPacket response\n");
			return false;
		}
		std::memcpy(&status, incomingTransformPacket.originalData.data() + 8, sizeof(NTSTATUS));
		if (status != 0)
		{
			LogW(L"[-] Failed logOffRequestPacket " + std::to_wstring(status) + L"\n");
			return false;
		}
	}
	else
	{
		LogW(L"[-] Failed recv logOffRequestPacket packet response " + std::to_wstring(GetLastError()) + L"\n");
		return false;
	}
	
	return true;
}

