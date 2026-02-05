#include "Log.hpp"
#include "YaraScanner.hpp"
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

class FanotifyWatcher
{
public:
    FanotifyWatcher(std::filesystem::path watch_dir, YaraScanner& scanner)
        : watch_dir_(std::move(watch_dir))
        , scanner_(scanner)
    {
    }

    bool RunFor(std::chrono::seconds duration)
    {
        std::error_code ec;
        std::filesystem::create_directories(watch_dir_, ec);
        if (ec)
        {
            LOG_ERR("failed to create watch dir {}: {}", watch_dir_.string(), ec.message());
        }

        int fan_fd = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK, O_RDONLY | O_LARGEFILE);
        if (fan_fd < 0)
        {
            LOG_ERR("fanotify_init failed (need root or CAP_SYS_ADMIN)");
            return false;
        }

        uint64_t mask = FAN_OPEN | FAN_CLOSE_WRITE | FAN_EVENT_ON_CHILD;
        if (fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_ONLYDIR, mask, AT_FDCWD, watch_dir_.c_str()) < 0)
        {
            LOG_ERR("fanotify_mark failed for {} (need root?)", watch_dir_.string());
            close(fan_fd);
            return false;
        }

        LOG_INF("fanotify+yara-x test start. watch dir: {}", watch_dir_.string());
        LOG_INF("write a file containing 'malware' or 'ransom' to trigger.");

        constexpr int kTimeoutMs = 1000;
        auto end_at = std::chrono::steady_clock::now() + duration;
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
            LOG_DBG("fanotify read returned: {}", length);
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
                            scanner_.ScanFile(path);
                        }
                    }
                    close(metadata->fd);
                }

                metadata = FAN_EVENT_NEXT(metadata, length);
            }
        }

        close(fan_fd);
        return true;
    }

private:
    std::filesystem::path watch_dir_;
    YaraScanner& scanner_;
};

}  // namespace

void test_yara_x_fanotify()
{
    LOG_INF("starting fanotify+yara-x test (requires root or CAP_SYS_ADMIN)");
    YaraScanner scanner(kTestRules);
    if (!scanner.Initialize())
    {
        return;
    }

    std::filesystem::path watch_dir = "/home/orchid/tool/a-ids/build";
    FanotifyWatcher watcher(watch_dir, scanner);
    watcher.RunFor(std::chrono::seconds(100));

    LOG_INF("fanotify+yara-x test done");
}
