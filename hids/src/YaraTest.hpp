#ifndef __YARA_TEST_HPP__
#define __YARA_TEST_HPP__

enum class YaraWatchMode {
    Inotify,
    Fanotify,
};

void run_yara_x_watch(YaraWatchMode mode);
void test_yara_x();
void test_yara_x_fanotify();

#endif  // __YARA_TEST_HPP__
