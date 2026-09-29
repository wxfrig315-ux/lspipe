#include "AV_PAIR.h"

AV_PAIR::AV_PAIR() :AvLen(0), AvId(0)
{
}

AV_PAIR::AV_PAIR(std::vector<uint8_t> vByteBuffer)
{
    deserialize(vByteBuffer);
}

std::vector<uint8_t> AV_PAIR::serialize()
{
    std::vector<uint8_t> result;
    appendLE(result, this->AvId);
    appendLE(result, this->AvLen);
    result = concat(result, this->Value);

    return result;
}

bool AV_PAIR::deserialize(const std::vector<uint8_t>& vByteBuffer)
{
    this->AvId = vByteBuffer[0] | (vByteBuffer[1] << 8);
    this->AvLen = vByteBuffer[2] | (vByteBuffer[3] << 8);

    this->Value.assign(vByteBuffer.begin() + 4, vByteBuffer.begin()+ 4 + AvLen);
    return true;
}

AttributeMap::AttributeMap()
{
}

std::vector<uint8_t> AttributeMap::getItem(uint8_t id)
{
    for (size_t i = 0; i < data.size(); i++)
    {
        if (id == this->data[i].AvId)
        {
            return this->data[i].Value;
        }
    }
}

std::vector<uint8_t> AttributeMap::serialize()
{
    std::vector<uint8_t> result;
    for (size_t i = 0; i < data.size(); i++)
    {
        result = concat(result, data[i].serialize());
    }
    return result;
}

bool AttributeMap::deserialize(const std::vector<uint8_t> &vByteBuffer)
{
    
    size_t offset = 0;
    AV_PAIR currentItem;
    

    while (offset + 4 <= vByteBuffer.size())
    {
        std::vector<uint8_t> sliced(vByteBuffer.begin() + offset, vByteBuffer.end());
        currentItem.deserialize(sliced);
        offset += currentItem.AvLen + 4;
        this->data.push_back(currentItem);

        if (currentItem.AvId == MsvAvDnsComputerName)
        {
            AV_PAIR tmp;
            std::vector<uint8_t> avDnsComputerName;

            std::vector<uint8_t> cifs_utf16le =
            {
                0x63, 0x00,  // 'c'
                0x69, 0x00,  // 'i'
                0x66, 0x00,  // 'f'
                0x73, 0x00,  // 's'
                0x2f, 0x00   // '/'
            };
            
            tmp.AvId = 0x9;
            avDnsComputerName = currentItem.Value;
            avDnsComputerName = concat(cifs_utf16le, avDnsComputerName);
            tmp.AvLen = avDnsComputerName.size();
            tmp.Value = avDnsComputerName;

            this->data.push_back(tmp);

        }
        
    }

    std::sort(data.begin(), data.end() -1, [](const AV_PAIR& a, const AV_PAIR& b)
    {
        return a.AvId < b.AvId;
    });
    return true;
}

