#include "spnego.h"

namespace SPNEGO 
{

    std::vector<uint8_t> GSS_API_SPNEGO_UUID{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 };

    // ASN.1 Tags
    constexpr uint8_t ASN1_SEQUENCE = 0x30;
    constexpr uint8_t ASN1_AID = 0x60;
    constexpr uint8_t ASN1_OID = 0x06;
    constexpr uint8_t ASN1_OCTET_STRING = 0x04;

    constexpr uint8_t ASN1_MECH_TYPE = 0xa0;
    constexpr uint8_t ASN1_SUPPORTED_MECH = 0xa1;
    constexpr uint8_t ASN1_MECH_TOKEN = 0xa2;
    constexpr uint8_t ASN1_RESPONSE_TOKEN = 0xa2;
    constexpr uint8_t ASN1_MECH_LIST_MIC = 0xa3;
    constexpr uint8_t ASN1_ENUMERATED = 0x0a;

    const std::map<std::wstring, std::vector<uint8_t>> mechType =
    {
        { L"NTLMSSP - Microsoft NTLM Security Support Provider",      { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a } },
        { L"MS KRB5 - Microsoft Kerberos 5",                          { 0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02 } },
        { L"KRB5 - Kerberos 5",                                       { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02 } },
        { L"KRB5 - Kerberos 5 - User to User",                        { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x03 } },
        { L"NEGOEX - SPNEGO Extended Negotiation Security Mechanism", { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x1e } }
    };

} // namespace SPNEGO

std::vector<uint8_t> asn1encode(const std::vector<uint8_t>& data)
{
    std::vector<uint8_t> result;
    size_t len = data.size();

    if (len <= 0x7F) {
        // Short form: 1 byte length
        result.push_back(static_cast<uint8_t>(len));
    }
    else if (len <= 0xFF)
    {
        // Long form: 0x81 + 1 byte length
        result.push_back(0x81);
        result.push_back(static_cast<uint8_t>(len));
    }
    else if (len <= 0xFFFF) {
        // Long form: 0x82 + 2 bytes length
        result.push_back(0x82);
        result.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        result.push_back(static_cast<uint8_t>(len & 0xFF));
    }
    else if (len <= 0xFFFFFF)
    {
        // Long form: 0x83 + 3 bytes length
        result.push_back(0x83);
        result.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
        result.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        result.push_back(static_cast<uint8_t>(len & 0xFF));
    }
    else if (len <= 0xFFFFFFFF)
    {
        // Long form: 0x84 + 4 bytes length
        result.push_back(0x84);
        result.push_back(static_cast<uint8_t>((len >> 24) & 0xFF));
        result.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
        result.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        result.push_back(static_cast<uint8_t>(len & 0xFF));
    }


    // Append the actual data after length encoding
    result.insert(result.end(), data.begin(), data.end());
    return result;
}



std::pair<std::vector<uint8_t>, uint32_t> asn1decode(std::vector<uint8_t> data)
{
    size_t offset = 0;
    uint8_t len1 = data[offset++];
    size_t length = 0;
    size_t totalHeaderSize = 1;

    if (len1 == 0x81)
    {
        if (data.size() < offset + 1)
        {
            //error_message(L"ASN.1 decode error: not enough data for 0x81");
        }
        length = data[offset];
        totalHeaderSize += 1;
        offset += 1;
    }
    else if (len1 == 0x82)
    {
        if (data.size() < offset + 2)
        {       
            //error_message(L"ASN.1 decode error: not enough data for 0x82");
        }
        length = data[offset] << 8 | data[offset + 1];
        offset += 2;
        totalHeaderSize += 2;
    }
    else  if (len1 == 0x83) 
    {
        if (data.size() < offset + 3)
        {
            //error_message(L"ASN.1 decode error: not enough data for 0x83");
        }
           
        length = (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2];
        offset += 3;
        totalHeaderSize += 3;
    }
    else if (len1 == 0x84) 
    {
        if (data.size() < offset + 4)
        {
            //error_message(L"ASN.1 decode error: not enough data for 0x84");
        }
           
        length = (data[offset] << 24) | (data[offset + 1] << 16) |(data[offset + 2] << 8) | data[offset + 3];
        offset += 4;
        totalHeaderSize += 4;
    }
    else
    {
        length = len1;
    }

    if (data.size() < offset + length) 
    {
        //error_message(L"ASN.1 decode error: length exceeds data size");
    }
    std::vector<uint8_t> content(data.begin() + offset, data.begin() + offset + length);
    return { content, totalHeaderSize + length };
}



GSSAPI::GSSAPI()
{
    this->fields[L"UUID"] = SPNEGO::GSS_API_SPNEGO_UUID;
}

GSSAPI::GSSAPI(std::vector<uint8_t> buf)
{
    this->fields[L"UUID"] = SPNEGO::GSS_API_SPNEGO_UUID;
    if (buf.empty() == false)
    {
        this->fromString(buf);
    }
}

GSSAPI::~GSSAPI()
{
}

void GSSAPI::fromString(const std::vector<uint8_t> &buf)
{
    /*
        Manual parse of the GSSAPI Header Format
        It should be something like
        AID = 0x60 TAG, BER Length
        OID = 0x06 TAG
        GSSAPI OID
        UUID data (BER Encoded)
        Payload
     */

    std::pair<std::vector<uint8_t>, uint8_t> decode_data;
    std::vector<uint8_t>tmp_vec = buf;

    uint8_t next_byte = tmp_vec[0];
    if (next_byte != SPNEGO::ASN1_AID)
    {
        //error_message(L"Unkown AID\n");
        return;
    }
    tmp_vec.assign(buf.begin() + 1, buf.end());

    decode_data = asn1decode(tmp_vec);
    // OID tag
    next_byte = decode_data.first[0];
    if (next_byte != SPNEGO::ASN1_OID)
    {
        //error_message(L"OID tag not found\n");
        return;
    }
    tmp_vec.assign(decode_data.first.begin() + 1, decode_data.first.end());

    decode_data = asn1decode(tmp_vec);

    this->fields[L"OID"] = decode_data.first;
    tmp_vec.assign(tmp_vec.begin() + decode_data.second, tmp_vec.end());
    this->fields[L"Payload"] = tmp_vec;
}


std::vector<uint8_t> GSSAPI::getData()
{
    std::vector<uint8_t> ans;
    ans.push_back(SPNEGO::ASN1_AID);
    ans = concat(ans, asn1encode(
        concat(
        { SPNEGO::ASN1_OID }, 
        concat(asn1encode(this->fields[L"UUID"]), this->fields[L"Payload"])
    )));
    return  ans;
}

SPNEGO_NegTokenResp::SPNEGO_NegTokenResp(std::vector<uint8_t> buf)
{
    if (buf.empty() == false)
    {
        this->fromString(buf);
    }
}

SPNEGO_NegTokenResp::SPNEGO_NegTokenResp()
{
}

SPNEGO_NegTokenResp::~SPNEGO_NegTokenResp()
{
}

std::vector<uint8_t> SPNEGO_NegTokenResp::getData()
{
    std::vector<uint8_t> tmp_vec;
    std::vector<uint8_t> ans(1,SPNEGO_NegTokenResp::SPNEGO_NEG_TOKEN_RESP);
    if (this->fields.count(L"NegState") &&
        this->fields.count(L"SupportMech") &&
        this->fields.count(L"ResponseToken")
        )
    {
        // server resp
        tmp_vec = asn1encode(this->fields[L"ResponseToken"]);
        tmp_vec = asn1encode(concat({ SPNEGO::ASN1_OCTET_STRING }, tmp_vec));
        tmp_vec = concat({ SPNEGO::ASN1_RESPONSE_TOKEN }, tmp_vec);
        tmp_vec = concat(asn1encode( concat({ SPNEGO::ASN1_OID }, asn1encode(this->fields[L"SupportMech"]))), tmp_vec);
        //tmp_vec = asn1encode(concat({ SPNEGO::ASN1_OID }, tmp_vec));
        tmp_vec = concat({ SPNEGO::ASN1_SUPPORTED_MECH }, tmp_vec);
        tmp_vec = concat(asn1encode(concat({ SPNEGO::ASN1_ENUMERATED }, asn1encode(this->fields[L"NegState"]))),tmp_vec);
        tmp_vec = asn1encode(concat ({ SPNEGO_NegTokenResp::SPNEGO_NEG_TOKEN_TARG }, tmp_vec));
        tmp_vec = asn1encode(concat({ SPNEGO::ASN1_SEQUENCE }, tmp_vec));
        tmp_vec = concat(ans, tmp_vec);
        return tmp_vec;

    }
    else
    {
        tmp_vec = asn1encode(this->fields[L"ResponseToken"]);
        tmp_vec = concat({ SPNEGO::ASN1_OCTET_STRING }, tmp_vec);
        tmp_vec = asn1encode(tmp_vec);
        tmp_vec = asn1encode(concat({ SPNEGO::ASN1_RESPONSE_TOKEN }, tmp_vec));
        tmp_vec = concat({ SPNEGO::ASN1_SEQUENCE }, tmp_vec);
        ans = concat(ans, asn1encode(tmp_vec));
        return ans;
    }
}

void SPNEGO_NegTokenResp::fromString(std::vector<uint8_t> buf)
{
    std::vector<uint8_t> tmp_vec = buf;
    uint8_t next_byte = tmp_vec[0];

    if (next_byte != SPNEGO_NegTokenResp::SPNEGO_NEG_TOKEN_RESP)
    {
        //error_message(L"NegTokenResp not found " + next_byte);
        return;
    }

    tmp_vec.assign(tmp_vec.begin() + 1, tmp_vec.end());

    std::pair<std::vector<uint8_t>, uint8_t> NegTokenResp = asn1decode(tmp_vec);

    next_byte = NegTokenResp.first[0];

    if (next_byte != SPNEGO::ASN1_SEQUENCE)
    {
        //error_message(L"SEQUENCE tag not found\n");
        return;
    }

    tmp_vec.assign(NegTokenResp.first.begin() + 1, NegTokenResp.first.end());


    std::pair<std::vector<uint8_t>, uint8_t> sequence_data = asn1decode(tmp_vec);

    next_byte = sequence_data.first[0];


    if (next_byte != SPNEGO::ASN1_MECH_TYPE)
    {
        if (next_byte != SPNEGO::ASN1_RESPONSE_TOKEN)
        {
            //error_message(L"MechType/ResponseToken tag not found\n");
            return;
        }
    }
    else
    {
        std::pair<std::vector<uint8_t>, uint8_t> decode_data;
        tmp_vec.assign(sequence_data.first.begin() + 1, sequence_data.first.end());

        decode_data = asn1decode(tmp_vec);
        next_byte = decode_data.first[0];

        if (next_byte != SPNEGO::ASN1_ENUMERATED)
        {
            //error_message(L"Enumerated tag not found");
            return;
        }
        std::pair<std::vector<uint8_t>, uint8_t> item;
        tmp_vec.assign(decode_data.first.begin() + 1, decode_data.first.end());

        item = asn1decode(tmp_vec);

        this->fields[L"NegState"] = item.first;
      
        /*if (item.first.size() <= item.second + 1)
        {
            return;
        }*/

        tmp_vec.assign(decode_data.second + sequence_data.first.begin() + 1, sequence_data.first.end());

        
        if (decode_data.first.size() == 0)
        {
            return;
        }

        next_byte = tmp_vec[0];
        if (next_byte != SPNEGO::ASN1_SUPPORTED_MECH)
        {
            if (next_byte != SPNEGO::ASN1_RESPONSE_TOKEN)
            {
                //error_message(L"Supported Mech/ResponseToken tag not found\n");
                return;
            }
        }
        else
        {
            std::pair<std::vector<uint8_t>, uint8_t> decode_data2;
            tmp_vec.assign(tmp_vec.begin() + 1, tmp_vec.end());
            decode_data2 = asn1decode(tmp_vec);

            next_byte = decode_data2.first[0];
            if (next_byte != SPNEGO::ASN1_OID)
            {
                //error_message(L"OID tag not found");
                return;
            }
            tmp_vec.assign(decode_data2.first.begin() + 1, decode_data2.first.end());
            
            std::pair<std::vector<uint8_t>, uint8_t> SupportMech = asn1decode(tmp_vec);

            this->fields[L"SupportMech"] = SupportMech.first;

            tmp_vec.assign(decode_data.second + sequence_data.first.begin() + 1 +1 + decode_data2.second, sequence_data.first.end());

            next_byte = tmp_vec[0];
            if (next_byte != SPNEGO::ASN1_RESPONSE_TOKEN)
            {
                //error_message(L"Response token tag not found\n");
                return;
            }
            
        }
        

    }
    tmp_vec.assign(tmp_vec.begin() + 2, tmp_vec.end());
    std::pair<std::vector<uint8_t>, uint8_t> decode_data = asn1decode(tmp_vec);
    next_byte = decode_data.first[0];
    if (next_byte != SPNEGO::ASN1_OCTET_STRING)
    {
        //error_message(L"Octet string token tag not found");
        return;
    }
    tmp_vec.assign(decode_data.first.begin() + 1, decode_data.first.end());
    decode_data = asn1decode(tmp_vec);
    this->fields[L"ResponseToken"] = decode_data.first;
}

SPNEGO_NegTokenInit::SPNEGO_NegTokenInit(): GSSAPI()
{
    this->mechTypes.push_back(SPNEGO::mechType.at(L"NTLMSSP - Microsoft NTLM Security Support Provider"));
}


SPNEGO_NegTokenInit::~SPNEGO_NegTokenInit()
{
    
}

void SPNEGO_NegTokenInit::fromString(std::vector<uint8_t> buf)
{
    GSSAPI::fromString(buf);
    std::vector<uint8_t> tmp_vec = this->fields[L"Payload"];

    uint8_t next_byte = tmp_vec[0];
    if (next_byte != SPNEGO_NegTokenInit::SPNEGO_NEG_TOKEN_INIT)
    {
        //error_message(L"NegTokenInit not Foundn\n");
        return;
    }

    tmp_vec.assign(tmp_vec.begin() + 1, tmp_vec.end());
    std::pair<std::vector<uint8_t>, uint8_t> decode_data = asn1decode(tmp_vec);

    next_byte = decode_data.first[0];

    if (next_byte != SPNEGO::ASN1_SEQUENCE)
    {
        //error_message(L"SEQUENCE tag not found\n");
    }

    tmp_vec.assign(decode_data.first.begin() + 1, decode_data.first.end());
    std::pair<std::vector<uint8_t>, uint8_t> decode_data2 = asn1decode(tmp_vec);

    next_byte = decode_data2.first[0];
    if (next_byte != SPNEGO::ASN1_MECH_TYPE)
    {
        //error_message(L"MechType tag not found\n");
        return;
    }
    tmp_vec.assign(decode_data2.first.begin() + 1, decode_data2.first.end());
    std::vector<uint8_t> remaining_data = tmp_vec;
    std::pair<std::vector<uint8_t>, uint8_t> decode_data3 = asn1decode(tmp_vec);
   
    next_byte = decode_data3.first[0];
    if (next_byte != SPNEGO::ASN1_SEQUENCE)
    {
        //error_message(L"SEQUENCE tag not found");
        return;
    }
    tmp_vec.assign(decode_data3.first.begin() + 1, decode_data3.first.end());
    std::pair<std::vector<uint8_t>, uint8_t> decode_data4 = asn1decode(tmp_vec);


    tmp_vec = decode_data4.first;
    while (tmp_vec.empty() == false)
    {
        next_byte = tmp_vec[0];
        if (next_byte != SPNEGO::ASN1_OID)
        {
            break;
        }

        tmp_vec.assign(tmp_vec.begin() + 1, tmp_vec.end());

        std::pair<std::vector<uint8_t>, uint8_t> item = asn1decode(tmp_vec);
        this->mechTypes.push_back(item.first);
        tmp_vec.assign(tmp_vec.begin() + item.second, tmp_vec.end());
    }

    if (remaining_data.size() < decode_data3.second)
    {
        return;
    }

    tmp_vec.assign(remaining_data.begin() + decode_data3.second, remaining_data.end());
    next_byte = tmp_vec[0];
    std::pair<std::vector<uint8_t>, uint8_t> mechToken;

    if (next_byte == SPNEGO::ASN1_MECH_TOKEN)
    {
        tmp_vec.assign(tmp_vec.begin() + 1, tmp_vec.end());
        mechToken = asn1decode(tmp_vec);

        next_byte = mechToken.first[0];
        if (next_byte == SPNEGO::ASN1_OCTET_STRING)
        {
            tmp_vec.assign(mechToken.first.begin() + 1, mechToken.first.end());
            mechToken = asn1decode(tmp_vec);
            this->fields[L"MechToken"] = mechToken.first;
        }
    }

}

std::vector<uint8_t> SPNEGO_NegTokenInit::getData()
{
    std::vector<uint8_t> encodedMechTypes;

    for (size_t i = 0; i < this->mechTypes.size(); i++)
    {
        encodedMechTypes.push_back(SPNEGO::ASN1_OID);
        const std::vector<uint8_t>& oid = this->mechTypes[i];
        encodedMechTypes = concat(encodedMechTypes, asn1encode(oid));
    }

    std::vector<uint8_t> mechToken;
    if (this->fields.count(L"MechToken") > 0)
    {
        mechToken = concat({ SPNEGO::ASN1_MECH_TOKEN }, 
            asn1encode(
            concat({ SPNEGO::ASN1_OCTET_STRING }, 
                asn1encode(this->fields[L"MechToken"]
                ))));
    }

    std::vector<uint8_t> ans;
    ans.push_back(SPNEGO_NegTokenInit::SPNEGO_NEG_TOKEN_INIT);
    
    std::vector<uint8_t> tmp_vec;

    tmp_vec = asn1encode(
        concat(
            { SPNEGO::ASN1_SEQUENCE },
            asn1encode(encodedMechTypes)
        ));
    tmp_vec = concat(tmp_vec, mechToken);
    tmp_vec = concat({ SPNEGO::ASN1_MECH_TYPE }, tmp_vec);
    tmp_vec = asn1encode(tmp_vec);
    tmp_vec = concat({ SPNEGO::ASN1_SEQUENCE }, tmp_vec);
    tmp_vec = asn1encode(tmp_vec);
    ans = concat(ans, tmp_vec);

    this->fields[L"Payload"] = ans;

    return GSSAPI::getData();
}