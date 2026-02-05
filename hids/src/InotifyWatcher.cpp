#include "YaraTest.hpp"

#include "Log.hpp"
#include "YaraScanner.hpp"

#include <chrono>
#include <filesystem>
#include <string>
#include <vector>

#include <limits.h>
#include <poll.h>
#include <sys/inotify.h>
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

class InotifyWatcher
{
public:
    InotifyWatcher(std::filesystem::path watch_dir, YaraScanner& scanner)
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

        int fd = inotify_init1(IN_NONBLOCK);
        if (fd < 0)
        {
            LOG_ERR("inotify_init1 failed");
            return false;
        }

        int wd = inotify_add_watch(fd, watch_dir_.c_str(), IN_CREATE | IN_MOVED_TO | IN_CLOSE_WRITE);
        if (wd < 0)
        {
            LOG_ERR("inotify_add_watch failed for {}", watch_dir_.string());
            close(fd);
            return false;
        }

        LOG_INF("inotify+yara-x test start. watch dir: {}", watch_dir_.string());
        LOG_INF("write a file containing 'malware' or 'ransom' to trigger.");

        constexpr int kTimeoutMs = 1000;
        auto end_at = std::chrono::steady_clock::now() + duration;
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
                    std::filesystem::path file_path = watch_dir_ / event->name;
                    LOG_INF("event: {}", file_path.string());
                    scanner_.ScanFile(file_path);
                }
                i += static_cast<ssize_t>(sizeof(inotify_event) + event->len);
            }
        }

        inotify_rm_watch(fd, wd);
        close(fd);
        return true;
    }

private:
    std::filesystem::path watch_dir_;
    YaraScanner& scanner_;
};

}  // namespace

void run_yara_x_watch(YaraWatchMode mode)
{
    switch (mode)
    {
    case YaraWatchMode::Inotify:
        test_yara_x();
        return;
    case YaraWatchMode::Fanotify:
        test_yara_x_fanotify();
        return;
    }
}

void test_yara_x()
{
    LOG_INF("starting inotify+yara-x test");
    YaraScanner scanner(kTestRules);
    if (!scanner.Initialize())
    {
        return;
    }

    std::filesystem::path watch_dir = "/home/orchid/tool/a-ids/build";
    InotifyWatcher watcher(watch_dir, scanner);
    watcher.RunFor(std::chrono::seconds(100));

    LOG_INF("inotify+yara-x test done");
}
