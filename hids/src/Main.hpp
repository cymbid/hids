#ifndef __MAIN_H__
#define __MAIN_H__

#include <nlohmann/json.hpp>
#include <thread>

namespace AC {
namespace AIds {

class Main
{
public:
    //    StartOption stOption;
    Main();

    bool reconstructionMode;
    bool bootstrappingConf;

    nlohmann::json conf;

    std::string confFile;
    //    std::string DEBUG_DIR;
    static bool requestStop;

    int start(pid_t ppid);
    int startMain(int argc, const char* const* argv, const char* const* env);
    int stop();

    void daemonize();
    //	int startMultiProcess();
    void resurrectProcess();
    void savePid(std::string fileName);
    void killPid(std::string fileName);
};

extern Main* g_main;

}  // namespace AIds
}  // namespace AC

#endif  //__MAIN_H__
