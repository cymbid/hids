#include "YaraTest.hpp"

#include "Log.hpp"

#include <chrono>
#include <filesystem>
#include <string>
#include <vector>

#include <limits.h>
#include <poll.h>
#include <sys/inotify.h>
#include <unistd.h>

extern "C" {
#include <yara_x.h>
}

namespace {

constexpr const char* kTestRules = R"YARARULE(
rule suspicious_string
{
    strings:
        $a = "malware" nocase
        $b = "ransom" nocase
    condition:
        any of them
}
)YARARULE";

void on_matching_rule(const YRX_RULE* rule, void* /*user_data*/)
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

void scan_file(YRX_SCANNER* scanner, const std::filesystem::path& path)
{
    auto result = yrx_scanner_scan_file(scanner, path.c_str());
    if (result != YRX_SUCCESS)
    {
        const char* err = yrx_last_error();
        LOG_ERR("scan failed: {} ({})", path.string(), err ? err : "unknown");
    }
}

}  // namespace

void test_yara_x()
{
    LOG_INF("starting inotify+yara-x test");
    YRX_RULES* rules = nullptr;
    if (yrx_compile(kTestRules, &rules) != YRX_SUCCESS || !rules)
    {
        const char* err = yrx_last_error();
        LOG_ERR("yara-x compile failed: {}", err ? err : "unknown");
        return;
    }

    LOG_INF("YARA-X rules compiled");
    YRX_SCANNER* scanner = nullptr;
    if (yrx_scanner_create(rules, &scanner) != YRX_SUCCESS || !scanner)
    {
        const char* err = yrx_last_error();
        LOG_ERR("yara-x scanner create failed: {}", err ? err : "unknown");
        yrx_rules_destroy(rules);
        return;
    }

    yrx_scanner_on_matching_rule(scanner, on_matching_rule, nullptr);

    std::filesystem::path watch_dir = "/home/orchid/tool/a-ids/build";
    std::error_code ec;
    std::filesystem::create_directories(watch_dir, ec);
    if (ec)
    {
        LOG_ERR("failed to create watch dir {}: {}", watch_dir.string(), ec.message());
    }

    int fd = inotify_init1(IN_NONBLOCK);
    if (fd < 0)
    {
        LOG_ERR("inotify_init1 failed");
        yrx_scanner_destroy(scanner);
        yrx_rules_destroy(rules);
        return;
    }

    int wd = inotify_add_watch(fd, watch_dir.c_str(), IN_CREATE | IN_MOVED_TO | IN_CLOSE_WRITE);
    if (wd < 0)
    {
        LOG_ERR("inotify_add_watch failed for {}", watch_dir.string());
        close(fd);
        yrx_scanner_destroy(scanner);
        yrx_rules_destroy(rules);
        return;
    }

    LOG_INF("inotify+yara-x test start. watch dir: {}", watch_dir.string());
    LOG_INF("write a file containing 'malware' or 'ransom' to trigger.");

    constexpr int kTimeoutMs = 1000;
    auto end_at = std::chrono::steady_clock::now() + std::chrono::seconds(100);
    std::vector<char> buffer(4096);

    while (std::chrono::steady_clock::now() < end_at)
    {
        pollfd pfd {fd, POLLIN, 0};
        int poll_ret = poll(&pfd, 1, kTimeoutMs);
        LOG_DBG("poll returned: {}", poll_ret);
        if (poll_ret <= 0)
        {
            continue;
        }

        ssize_t length = read(fd, buffer.data(), buffer.size());
        LOG_DBG("inotify read returned: {}", length);
        if (length <= 0)
        {
            continue;
        }

        ssize_t i = 0;
        while (i < length)
        {
            auto* event = reinterpret_cast<inotify_event*>(buffer.data() + i);
            LOG_DBG("inotify event: mask=0x{:x} name='{}', len={}", event->mask, event->name, event->len);
            if (event->len > 0 && !(event->mask & IN_ISDIR))
            {
                std::filesystem::path file_path = watch_dir / event->name;
                LOG_INF("event: {}", file_path.string());
                scan_file(scanner, file_path);
            }
            i += static_cast<ssize_t>(sizeof(inotify_event) + event->len);
        }
    }

    inotify_rm_watch(fd, wd);
    close(fd);

    yrx_scanner_destroy(scanner);
    yrx_rules_destroy(rules);

    LOG_INF("inotify+yara-x test done");
}
