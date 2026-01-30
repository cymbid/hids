#include "Util.hpp"

namespace AC {
namespace AIds {

std::string Util::hexlify(const ByteData& data)
{
    // std::string T = "0123456789ABCDEF";
    std::string hex;
    hex.reserve(2 * data.size());

    for (uint8_t c : data)
    {
        hex.push_back(hexUpperChars[c >> 4U]);
        hex.push_back(hexUpperChars[c & 15U]);
    }
    return hex;
};

ByteData Util::unhexlify(const std::string& hex)
{
    static std::vector<int> Tmap = getTmap();

    ByteData bin;
    bin.reserve(hex.size() / 2);

    bool even = true;
    uint8_t value = 0;
    for (char ch : hex)
    {
        auto c = static_cast<uint8_t>(ch);
        if (Tmap[c] == -1)
        {
            continue;
        }

        value = (value << 4U) + Tmap[c];
        even = !even;

        if (even)
        {
            bin.push_back((char(value)));
        }
    }
    return bin;
};

std::vector<std::vector<std::string>> Util::parseCSV(const std::string& csvSource)
{
    bool inQuote(false);
    bool newLine(false);
    std::string field;
    std::vector<std::vector<std::string>> lines;
    std::vector<std::string> line;

    std::string::const_iterator aChar = csvSource.begin();
    while (aChar != csvSource.end())
    {
        switch (*aChar)
        {
        case '"':
            newLine = false;
            inQuote = !inQuote;
            break;

        case ',':
            newLine = false;
            if (inQuote == true)
            {
                field += *aChar;
            }
            else
            {
                line.push_back(field);
                field.clear();
            }
            break;

        case '\n':
        case '\r':
            if (inQuote == true)
            {
                field += *aChar;
            }
            else
            {
                if (newLine == false)
                {
                    line.push_back(field);
                    lines.push_back(line);
                    field.clear();
                    line.clear();
                    newLine = true;
                }
            }
            break;

        default:
            newLine = false;
            field.push_back(*aChar);
            break;
        }

        aChar++;
    }

    if (field.size())
        line.push_back(field);

    if (line.size())
        lines.push_back(line);

    return lines;
}

enum class CSVState { UnquotedField, QuotedField, QuotedQuote };
std::vector<std::string> Util::readCSVRow(const std::string& row)
{
    CSVState state = CSVState::UnquotedField;
    std::vector<std::string> fields {""};
    size_t i = 0;  // index of the current field
    for (char c : row)
    {
        switch (state)
        {
        case CSVState::UnquotedField:
            switch (c)
            {
            case ',':  // end of field
                fields.push_back("");
                i++;
                break;
            case '"':
                state = CSVState::QuotedField;
                break;
            default:
                fields[i].push_back(c);
                break;
            }
            break;
        case CSVState::QuotedField:
            switch (c)
            {
            case '"':
                state = CSVState::QuotedQuote;
                break;
            default:
                fields[i].push_back(c);
                break;
            }
            break;
        case CSVState::QuotedQuote:
            switch (c)
            {
            case ',':  // , after closing quote
                fields.push_back("");
                i++;
                state = CSVState::UnquotedField;
                break;
            case '"':  // "" -> "
                fields[i].push_back('"');
                state = CSVState::QuotedField;
                break;
            default:  // end of quote
                state = CSVState::UnquotedField;
                break;
            }
            break;
        }
    }
    return fields;
}

bool Util::readCSVRow(const std::string& row, std::function<void(uint32_t idx, const std::string&)> func)
{
    CSVState state = CSVState::UnquotedField;
    std::string field;
    size_t i = 0;  // index of the current field
    for (char c : row)
    {
        switch (state)
        {
        case CSVState::UnquotedField:
            switch (c)
            {
            case ',':  // end of field
                func(i, field);
                field.clear();
                i++;
                break;
            case '"':
                state = CSVState::QuotedField;
                break;
            default:
                field.push_back(c);
                break;
            }
            break;
        case CSVState::QuotedField:
            switch (c)
            {
            case '"':
                state = CSVState::QuotedQuote;
                break;
            default:
                field.push_back(c);
                break;
            }
            break;
        case CSVState::QuotedQuote:
            switch (c)
            {
            case ',':  // , after closing quote
                func(i, field);
                field.clear();
                i++;
                state = CSVState::UnquotedField;
                break;
            case '"':  // "" -> "
                field.push_back('"');
                state = CSVState::QuotedField;
                break;
            default:  // end of quote
                state = CSVState::UnquotedField;
                break;
            }
            break;
        }
    }
    if (field.empty() == false)
    {
        return false;
    }
    else
    {
        func(i, field);
        return true;
    }
}

const std::array<char, 16> Util::hexUpperChars = {'0', '1', '2', '3', '4', '5', '6', '7',
                                                  '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
const std::array<char, 16> Util::hexLowerChars = {'0', '1', '2', '3', '4', '5', '6', '7',
                                                  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

std::vector<int> Util::getTmap()
{
    static std::vector<int> Tmap(256, -1);
    if (Tmap[hexUpperChars[0]] == -1)
    {
        for (int i = 0; i < 16; i++)
        {
            Tmap[hexUpperChars[i]] = i;
        }
        for (int i = 10; i < 16; i++)
        {
            Tmap[hexLowerChars[i]] = i;
        }
    }
    return Tmap;
}

// uint64_t Util::secMarkToTime64(uint32_t secMark)
// {

// }

uint64_t Util::getTime64()
{
    // get epoctime since 2004-01-01 00:00:00.000 UTC

    // 2004-01-01 00:00:00.000 UTC to timepoint
    // static std::chrono::time_point<std::chrono::system_clock> stTp =
    // std::chrono::system_clock::from_time_t(1072915200);

    // std::chrono::duration<uint64_t, std::chrono::milliseconds> epocDur = (std::chrono::system_clock::now() - stTp);

    // std::chrono::duration<uint64_t, std::chrono::milliseconds> epocDur;
    auto epocDur = std::chrono::system_clock::now().time_since_epoch();
    // UTC to TAI
    epocDur += std::chrono::seconds(32) - std::chrono::seconds(1072915200);
    // return std::chrono::duration_cast<uint64_t, std::chrono::milliseconds>(epocDur).count();
    return std::chrono::duration_cast<std::chrono::milliseconds>(epocDur).count();
}

}  // namespace AIds
}  // namespace AC