#pragma once
#include <string>
#include <vector>
#include <iostream>
#include <map>
#include "utils.h"
#include "DirectTCPTransportHeader.h"

std::vector<uint8_t> asn1encode(const std::vector<uint8_t>& data);
std::pair < std::vector<uint8_t>, uint32_t > asn1decode(std::vector<uint8_t> data);

class SPNEGO_NegTokenResp
{
public:
	uint8_t SPNEGO_NEG_TOKEN_RESP = 0xa1;
	uint8_t	SPNEGO_NEG_TOKEN_TARG = 0xa0;
	std::map<std::wstring, std::vector<uint8_t>> fields;
	std::vector<uint8_t> getData();

	SPNEGO_NegTokenResp(std::vector<uint8_t> buf);
	SPNEGO_NegTokenResp();
	~SPNEGO_NegTokenResp();
	void fromString(std::vector<uint8_t> buf);
private:

};

class GSSAPI
{
public:
	GSSAPI();
	GSSAPI(std::vector<uint8_t> buf);
	~GSSAPI();
	void fromString(const std::vector<uint8_t> &buf);
	std::vector<uint8_t> getData();
	std::map<std::wstring, std::vector<uint8_t>> fields;

};


class SPNEGO_NegTokenInit :public GSSAPI
{
public:
	uint8_t SPNEGO_NEG_TOKEN_INIT = 0xa0;
	SPNEGO_NegTokenInit();
	~SPNEGO_NegTokenInit();
	std::vector<uint8_t> getData();
	std::vector<std::vector<uint8_t>> mechTypes;
	void fromString(std::vector<uint8_t> buf);
private:

};


