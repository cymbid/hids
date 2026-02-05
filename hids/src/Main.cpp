
#include "Main.hpp"

#include "Log.hpp"
#include "Util.hpp"
#include "YaraTest.hpp"
#include "config_a-ids.h"
#include "cxxopts.hpp"

#include <array>
#include <chrono>
#include <csignal>
#include <fstream>
#include <iostream>
#include <map>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>
#include <vector>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace std::chrono_literals;

namespace AC {
namespace AIds {

Main* g_main;

bool Main::requestStop = false;

Main::Main()
{
}

void sigint_handler(int signo)
{
    LOG_INF("signal recv: {}", signo);
    g_main->stop();
    signal(SIGINT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);
}

int Main::start(pid_t ppid)
{
    LOG_INF("sever starting");

    //    spdlog::dump_backtrace();
    LOG_DBG("Name: {}", PACKAGE_NAME);
    LOG_DBG("Vendor: {}", PACKAGE_VENDOR);
    LOG_DBG("Description Summary: {}", PACKAGE_DESCRIPTION_SUMMARY);
    LOG_DBG("Version: {}", VERSION);
    LOG_DBG("Git Version: {}", GIT_VERSION);
    LOG_DBG("Build Type: {}", CMAKE_BUILD_TYPE);
    LOG_DBG("System Name: {}", CMAKE_SYSTEM);
    LOG_DBG("C Compiler Id: {}", CMAKE_C_COMPILER_ID);
    LOG_DBG("C Compiler Version: {}", CMAKE_C_COMPILER_VERSION);
    LOG_DBG("C Flags: {}", CMAKE_C_FLAGS);
    LOG_DBG("Cxx Compiler Id: {}", CMAKE_CXX_COMPILER_ID);
    LOG_DBG("Cxx Compiler Version: {}", CMAKE_CXX_COMPILER_VERSION);
    LOG_DBG("Cxx Flags: {}", CMAKE_CXX_FLAGS);
    LOG_DBG("LIB Openssl Version: {}", OPENSSL_VERSION_STR);
    LOG_DBG("LIB Openssl Version text: {}", OPENSSL_VERSION_STR);
    // LOG_DBG("LIB MySQL Client Version: {}",  mysql_get_client_info());
    //    LOG_DBG("LIB Protocol Buffer Version: {}",  GOOGLE_PROTOBUF_VERSION;
    LOG_DBG("Cpp Version: {}", __cplusplus);

    LOG_DBG("conf: {}", conf.dump(2));

    // signal( SIGINT, sigint_handler);
    // signal( SIGTERM, sigint_handler);

    test_yara_x();

    LOG_DBG("finish");
    return 0;
}

int Main::stop()
{
    LOG_INF("server stopping");
    // server->stop();
    return 0;
}

int Main::startMain(int argc, const char* const* argv, [[maybe_unused]] const char* const* env)
{
    std::string address;
    std::string user;
    std::string password;
    bool reconnect;
    int message_count;
    bool sendMsg;
    bool runYaraTest;
    bool runFanotifyTest;
    std::string yaraWatchMode;

    cxxopts::Options options(EXECUTABLE_NAME, "Ship Network Monitoring System.");
    options.add_options()                                                           //
        ("s,send", "send message", cxxopts::value<bool>()->default_value("false"))  //
        // ("r,recv", "receive message")  //
        ("a,address", "connect and send to URL",
         cxxopts::value<std::string>()->default_value("192.168.50.21:5672/examples"))                           //
        ("u,user", "authenticate as USER", cxxopts::value<std::string>()->default_value("USER"))                //
        ("p,password", "authenticate with PASSWORD", cxxopts::value<std::string>()->default_value("PASSWORD"))  //
        ("R,reconnect", "reconnect on connection failure", cxxopts::value<bool>()->default_value("false"))      //
        ("m,messages", "send COUNT messages", cxxopts::value<int>()->default_value("100"))                      //
        ("y,yara-test", "run inotify+yara-x test", cxxopts::value<bool>()->default_value("false"))              //
        ("f,fanotify-test", "run fanotify+yara-x test", cxxopts::value<bool>()->default_value("false"))         //
        ("Y,yara-watch", "select yara watch mode (inotify|fanotify)",
         cxxopts::value<std::string>()->default_value(""))  //

        ("h,help", "produce help message")  //
        ("version", "print version");       //

    try
    {
        auto vm = options.parse(argc, (char**&)argv);

        if (vm.count("help"))
        {
            fmt::print("{}\n", options.help());
            return true;
        }

        if (vm.count("version"))
        {
            fmt::print("Version: {}\n", VERSION);
            fmt::print("System: {}\n", CMAKE_SYSTEM);
            fmt::print("Compiler Version: {}\n", CMAKE_CXX_COMPILER_VERSION);
            fmt::print("OpenSSL Version: {}\n", OPENSSL_VERSION_STR);
            fmt::print("Version: {}\n", VERSION);
            return true;
        }

        // std::ifstream ifs(vm["conf"].as<std::string>());

        // if (ifs.is_open())
        // {
        //     conf = nlohmann::json::parse(ifs, nullptr, true, true);
        //     ifs.close();
        // }

        address = vm["address"].as<std::string>();
        user = vm["user"].as<std::string>();
        password = vm["password"].as<std::string>();
        reconnect = vm["reconnect"].as<bool>();
        message_count = vm["messages"].as<int>();
        sendMsg = vm["send"].as<bool>();
        runYaraTest = vm["yara-test"].as<bool>();
        runFanotifyTest = vm["fanotify-test"].as<bool>();
        yaraWatchMode = vm["yara-watch"].as<std::string>();

        // for (auto &x : vm.arguments())
        // {
        //     conf[x.key()] = x.value();
        // }
    }
    catch (cxxopts::exceptions::exception& ee)
    {
        fmt::print("option error: {}\n", ee.what());
        fmt::print("{}\n", options.help());
        return 1;
    }
    catch (nlohmann::json::exception& ee)
    {
        fmt::print("conf error: {}, {}\n", confFile, ee.what());
        fmt::print("{}\n", options.help());
        return 1;
    }
    catch (std::exception& ee)
    {
        fmt::print("error: {}\n", ee.what());
        fmt::print("{}\n", options.help());
        return 1;
    }

    if (!yaraWatchMode.empty())
    {
        if (yaraWatchMode == "inotify")
        {
            run_yara_x_watch(YaraWatchMode::Inotify);
        }
        else if (yaraWatchMode == "fanotify")
        {
            run_yara_x_watch(YaraWatchMode::Fanotify);
        }
        else
        {
            LOG_ERR("invalid yara-watch value: {} (use inotify|fanotify)", yaraWatchMode);
            return 1;
        }
    }
    else
    {
        if (runYaraTest)
        {
            test_yara_x();
        }

        if (runFanotifyTest)
        {
            test_yara_x_fanotify();
        }
    }

    return 0;
}

void Main::daemonize()
{
    pid_t pid = fork();
    if (pid < 0)
    {
        fprintf(stderr, "fork() failed: %s\n", strerror(errno));
        exit(-1);
    }
    else if (pid > 0)
    { /* parent */
        exit(0);
    }
    /* child */
    if (setsid() == -1)
    {
        fprintf(stderr, "setsid() failed: %s\n", strerror(errno));
        exit(-2);
    }
}

void Main::savePid(std::string fileName)
{
    std::ofstream ofs(fileName);

    ofs << getpid();
}

void Main::killPid(std::string fileName)
{
    std::ifstream ifs(fileName);
    int32_t pid = 0;
    ifs >> pid;

    if (pid > 0)
    {
        kill(pid, SIGTERM);
    }
}

void Main::resurrectProcess()
{
    std::chrono::steady_clock::time_point privTime = std::chrono::steady_clock::now() - std::chrono::seconds(20);
    int retryCount = 0;

    pid_t childProcess = 0;
    while (true)
    {
        if (childProcess != 0)
        {
            int status;
            pid_t pid_child = waitpid(childProcess, &status, WNOHANG);
            if (pid_child == 0)
            {
                if (Main::requestStop)
                {
                    //                    LOG_INFO << "kill child : " << childProcess;
                    kill(childProcess, SIGINT);
                }
                continue;
            }

            if (WIFEXITED(status))
            {
                //                LOG_INFO << "Work Process terminated. return code: " << WEXITSTATUS(status);
                return;
            }

            if (WIFSIGNALED(status))
            {
                //                LOG_INFO << "Work Process terminated. signal: " << WTERMSIG(status);
                if (WTERMSIG(status) != SIGABRT)
                {
                    return;
                }
            }
        }

        if (Main::requestStop)
        {
            return;
        }

        std::chrono::steady_clock::time_point currentTime = std::chrono::steady_clock::now();
        std::chrono::duration<double> time_span = (currentTime - privTime);
        if (time_span.count() > 20)
        {
            retryCount = 0;
        }
        else
        {
            retryCount++;
            if (retryCount > 5)
            {
                //                LOG_INFO << "Work Process restart fail.";
                return;
            }
        }

        privTime = currentTime;

        pid_t pid = fork();
        if (pid < 0)
        {
            fprintf(stderr, "fork() failed: %s\n", strerror(errno));
            exit(-1);
        }
        else if (pid == 0)
        { /* child */
            //            LOG_INFO << "Child process start";

            start(0);
            return;
        }

        childProcess = pid;
        //        LOG_INFO << "Child process: " << childProcess;

        sleep(1);
    }
}

}  // namespace AIds
}  // namespace AC
