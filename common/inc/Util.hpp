
#ifndef __UTIL_H__
#define __UTIL_H__

#include "Log.hpp"
#include "fmt/color.h"
#include "fmt/core.h"
#include "fmt/format.h"

#include <functional>
#include <string>
#include <vector>

namespace AC {
namespace AIds {

using ByteData = std::vector<uint8_t>;

#define SetBit(x, y) (x |= (1 << static_cast<uint8_t>(y)))
#define ClearBit(x, y) (x &= ~(1 << static_cast<uint8_t>(y)))
#define TestBit(x, y) (x & (1 << static_cast<uint8_t>(y)))

class Util
{
public:
    static std::string hexlify(const ByteData& data);
    static ByteData unhexlify(const std::string& hex);

    static std::vector<std::vector<std::string>> parseCSV(const std::string& csvSource);

    static std::vector<std::string> readCSVRow(const std::string& row);
    static bool readCSVRow(const std::string& row, std::function<void(uint32_t idx, const std::string&)> func);

    // static uint64_t secMarkToTime64(uint32_t secMark);
    static uint64_t getTime64();

    template <typename T>
    static std::vector<T> parseCSV(const std::string& csvSource,
                                   std::function<void(uint32_t row, uint32_t col, const std::string& field, T&)> func)
    {
        bool inQuote(false);
        bool newLine(false);
        std::string field;
        std::string::const_iterator aChar = csvSource.begin();
        std::vector<T> lines;

        uint32_t row = 0;
        while (aChar != csvSource.end())
        {
            T& line = lines.emplace_back();
            uint32_t col = 0;  // index of the current field
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
                        func(row, col, field, line);
                        field.clear();
                        col++;
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
                            func(row, col, field, line);
                            field.clear();
                            newLine = true;
                            row++;
                        }
                    }
                    break;

                default:
                    newLine = false;
                    field.push_back(*aChar);
                    break;
                }

                aChar++;

                if (newLine)
                {
                    break;
                }
            }

            if (field.size())
            {
                func(row, col, field, line);
                field.clear();
            }
        }
        return lines;
    }

private:
    static const std::array<char, 16> hexUpperChars;
    static const std::array<char, 16> hexLowerChars;

    static std::vector<int> getTmap();
};

}  // namespace AIds
}  // namespace AC

#define FMT_FORMAT_ENUM(enum_type)         \
    inline uint32_t format_as(enum_type x) \
    {                                      \
        return fmt::underlying(x);         \
    }

namespace fmt {
template <>
struct formatter<AC::AIds::ByteData>
{
    constexpr auto parse(format_parse_context& ctx)
    {
        return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const AC::AIds::ByteData& p, FormatContext& ctx)
    {
        std::string out;
        for (auto& i : p)
        {
            out += fmt::format("{:02X}", i);
        }
        return format_to(ctx.out(), "{}", out);
    }
};
}  // namespace fmt

// namespace nlohmann {
// template <typename Clock, typename Duration>
// struct adl_serializer<std::chrono::time_point<Clock, Duration>>
// {
//     static void to_json(json& j, const std::chrono::time_point<Clock, Duration>& tp)
//     {
//         j["since_epoch"] = std::chrono::duration_cast<std::chrono::microseconds>(tp.time_since_epoch()).count();
//         j["unit"] = "microseconds";
//     }
// };
// }  // namespace nlohmann

#endif  //__UTIL_H__
