#pragma once

#include "Log.hpp"

#include <filesystem>
#include <string>

extern "C" {
#include <yara_x.h>
}

class YaraScanner
{
public:
    explicit YaraScanner(std::string rules_text)
        : rules_text_(std::move(rules_text))
    {
    }
    ~YaraScanner()
    {
        if (scanner_)
        {
            yrx_scanner_destroy(scanner_);
        }
        if (rules_)
        {
            yrx_rules_destroy(rules_);
        }
    }

    YaraScanner(const YaraScanner&) = delete;
    YaraScanner& operator=(const YaraScanner&) = delete;

    bool Initialize()
    {
        if (yrx_compile(rules_text_.c_str(), &rules_) != YRX_SUCCESS || !rules_)
        {
            const char* err = yrx_last_error();
            LOG_ERR("yara-x compile failed: {}", err ? err : "unknown");
            return false;
        }

        LOG_INF("YARA-X rules compiled");
        if (yrx_scanner_create(rules_, &scanner_) != YRX_SUCCESS || !scanner_)
        {
            const char* err = yrx_last_error();
            LOG_ERR("yara-x scanner create failed: {}", err ? err : "unknown");
            return false;
        }

        yrx_scanner_on_matching_rule(scanner_, OnMatchingRule, nullptr);
        return true;
    }

    bool ScanFile(const std::filesystem::path& path)
    {
        if (!scanner_)
        {
            LOG_ERR("yara-x scanner not initialized");
            return false;
        }

        auto result = yrx_scanner_scan_file(scanner_, path.c_str());
        if (result != YRX_SUCCESS)
        {
            const char* err = yrx_last_error();
            LOG_ERR("scan failed: {} ({})", path.string(), err ? err : "unknown");
            return false;
        }

        return true;
    }

private:
    static void OnMatchingRule(const YRX_RULE* rule, void* /*user_data*/)
    {
        LOG_DBG("on_matching_rule called");
        const uint8_t* ident = nullptr;
        size_t len = 0;
        if (yrx_rule_identifier(rule, &ident, &len) == YRX_SUCCESS && ident && len > 0)
        {
            std::string rule_name(reinterpret_cast<const char*>(ident), len);
            LOG_INF("YARA-X match: {}", rule_name);
        }
        else
        {
            LOG_INF("YARA-X match: <unknown>");
        }
    }

    std::string rules_text_;
    YRX_RULES* rules_ = nullptr;
    YRX_SCANNER* scanner_ = nullptr;
};