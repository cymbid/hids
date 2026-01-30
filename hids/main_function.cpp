
#include "Log.hpp"
#include "Main.hpp"

#ifdef USE_BACKWARD
#include "backward.hpp"
#endif

int main(int argc, const char* const* argv, const char* const* env)
{
#ifdef USE_BACKWARD
    backward::SignalHandling backwardTlsTest;
#endif
    spdlog::set_level(spdlog::level::trace);
    spdlog::set_pattern("%^[%H:%M:%S.%e %L %@ %!]%$ %v");

    static AC::AIds::Main main;

    AC::AIds::g_main = &main;

    return main.startMain(argc, argv, env);
}
