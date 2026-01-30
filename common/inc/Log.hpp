
#ifndef __LOG_H__
#define __LOG_H__

#include "config_a-ids.h"
#include "fmt/color.h"
#include "fmt/core.h"
#include "spdlog/spdlog.h"

#define __FILENAME__ ((__FILE__) + (SOURCE_PATH_SIZE))

#if !defined(LOG_ACTIVE_LEVEL)
#define LOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#endif

#define LOG_FUNC(...) spdlog::default_logger_raw()->log({}, __VA_ARGS__)

#if LOG_ACTIVE_LEVEL <= SPDLOG_LEVEL_TRACE
#define LOG_TRA(...)                                                                                               \
    spdlog::default_logger_raw()->log(                                                                             \
        spdlog::source_loc {__FILENAME__, __LINE__, static_cast<const char*>(__FUNCTION__)}, spdlog::level::trace, \
        __VA_ARGS__)
#else
#define LOG_TRA(...) (void)0
#endif

#if LOG_ACTIVE_LEVEL <= SPDLOG_LEVEL_DEBUG
#define LOG_DBG(...)                                                                                               \
    spdlog::default_logger_raw()->log(                                                                             \
        spdlog::source_loc {__FILENAME__, __LINE__, static_cast<const char*>(__FUNCTION__)}, spdlog::level::debug, \
        __VA_ARGS__);
#else
#define LOG_DBG(...) (void)0
#endif

#if LOG_ACTIVE_LEVEL <= SPDLOG_LEVEL_INFO
#define LOG_INF(...)                                                                                              \
    spdlog::default_logger_raw()->log(                                                                            \
        spdlog::source_loc {__FILENAME__, __LINE__, static_cast<const char*>(__FUNCTION__)}, spdlog::level::info, \
        __VA_ARGS__);
#else
#define LOG_INF(...) (void)0
#endif

#if LOG_ACTIVE_LEVEL <= SPDLOG_LEVEL_WARN
#define LOG_WRN(...)                                                                                              \
    spdlog::default_logger_raw()->log(                                                                            \
        spdlog::source_loc {__FILENAME__, __LINE__, static_cast<const char*>(__FUNCTION__)}, spdlog::level::warn, \
        __VA_ARGS__);
#else
#define LOG_WRN(...) (void)0
#endif

#if LOG_ACTIVE_LEVEL <= SPDLOG_LEVEL_ERROR
#define LOG_ERR(...)                                                                                             \
    spdlog::default_logger_raw()->log(                                                                           \
        spdlog::source_loc {__FILENAME__, __LINE__, static_cast<const char*>(__FUNCTION__)}, spdlog::level::err, \
        __VA_ARGS__);
#else
#define LOG_ERR(...) (void)0
#endif

#endif  //__LOG_H__
