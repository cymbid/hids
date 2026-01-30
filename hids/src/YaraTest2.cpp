#include "Log.hpp"
#include "YaraTest.hpp"

#include <array>
#include <chrono>
#include <filesystem>
#include <string>
#include <vector>

#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <sys/fanotify.h>
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

void scan_path(YRX_SCANNER* scanner, const std::filesystem::path& path)
{
    auto result = yrx_scanner_scan_file(scanner, path.c_str());
    if (result != YRX_SUCCESS)
    {
        const char* err = yrx_last_error();
        LOG_ERR("scan failed: {} ({})", path.string(), err ? err : "unknown");
    }
}

std::filesystem::path path_from_fd(int fd)
{
    std::array<char, PATH_MAX> link_target {};
    std::string proc_path = "/proc/self/fd/" + std::to_string(fd);
    ssize_t len = readlink(proc_path.c_str(), link_target.data(), link_target.size() - 1);
    if (len <= 0)
    {
        return {};
    }
    link_target[static_cast<size_t>(len)] = '\0';
    return std::filesystem::path(link_target.data());
}

}  // namespace

void test_yara_x_fanotify()
{
    LOG_INF("starting fanotify+yara-x test (requires root or CAP_SYS_ADMIN)");

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

    int fan_fd = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK, O_RDONLY | O_LARGEFILE);
    if (fan_fd < 0)
    {
        LOG_ERR("fanotify_init failed (need root or CAP_SYS_ADMIN)");
        yrx_scanner_destroy(scanner);
        yrx_rules_destroy(rules);
        return;
    }

    uint64_t mask = FAN_OPEN | FAN_CLOSE_WRITE | FAN_EVENT_ON_CHILD;
    if (fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_ONLYDIR, mask, AT_FDCWD, watch_dir.c_str()) < 0)
    {
        LOG_ERR("fanotify_mark failed for {} (need root?)", watch_dir.string());
        close(fan_fd);
        yrx_scanner_destroy(scanner);
        yrx_rules_destroy(rules);
        return;
    }

    LOG_INF("fanotify+yara-x test start. watch dir: {}", watch_dir.string());
    LOG_INF("write a file containing 'malware' or 'ransom' to trigger.");

    constexpr int kTimeoutMs = 1000;
    auto end_at = std::chrono::steady_clock::now() + std::chrono::seconds(100);
    std::vector<char> buffer(4096);

    while (std::chrono::steady_clock::now() < end_at)
    {
        pollfd pfd {fan_fd, POLLIN, 0};
        int poll_ret = poll(&pfd, 1, kTimeoutMs);
        LOG_DBG("poll returned: {}", poll_ret);
        if (poll_ret <= 0)
        {
            continue;
        }

        ssize_t length = read(fan_fd, buffer.data(), buffer.size());
        LOG_DBG("inotify read returned: {}", length);
        if (length <= 0)
        {
            continue;
        }

        auto* metadata = reinterpret_cast<fanotify_event_metadata*>(buffer.data());
        while (FAN_EVENT_OK(metadata, length))
        {
            LOG_DBG("fanotify event: fd={}, mask={:#llx}, vers: {}", metadata->fd,
                    static_cast<unsigned long long>(metadata->mask), metadata->vers);
            if (metadata->vers != FANOTIFY_METADATA_VERSION)
            {
                LOG_ERR("fanotify metadata version mismatch");
                break;
            }

            if (metadata->fd >= 0)
            {
                if (metadata->mask & FAN_CLOSE_WRITE)
                {
                    auto path = path_from_fd(metadata->fd);
                    if (!path.empty() && std::filesystem::is_regular_file(path))
                    {
                        LOG_INF("event: {}", path.string());
                        scan_path(scanner, path);
                    }
                }
                close(metadata->fd);
            }

            metadata = FAN_EVENT_NEXT(metadata, length);
        }
    }

    close(fan_fd);
    yrx_scanner_destroy(scanner);
    yrx_rules_destroy(rules);

    LOG_INF("fanotify+yara-x test done");
}
