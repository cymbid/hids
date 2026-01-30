#include "config_a-ids.h"

#include <gtest/gtest.h>
#ifdef USE_BACKWARD
#include "backward.hpp"
#endif
#include <spdlog/spdlog.h>

int main(int argc, char* argv[])
{
    spdlog::set_level(spdlog::level::trace);
    spdlog::set_pattern("%^[%H:%M:%S.%e %t %L %@ %!]%$ %v");
#ifdef USE_BACKWARD
    backward::SignalHandling backwardTlsTest;
#endif
    testing::InitGoogleTest(&argc, argv);

    int result = RUN_ALL_TESTS();

    return result;
}
