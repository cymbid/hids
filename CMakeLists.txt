cmake_minimum_required(VERSION 3.18)

MESSAGE(STATUS "==========================================")
MESSAGE(STATUS "Orchid ids")
MESSAGE(STATUS "==========================================")
project(a-ids)

set(CMAKE_CXX_STANDARD 17)

option(USE_BACKWARD "backward 사용" ON)
option(BUILD_TESTING "test 빌드" ON)

# vscode intelisense를 위한 설정
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 빌드 속도 향상을 위해 ccache 도입
# XCode는 몇가지 처리를 더 해야 CCache를 이용할 수 있습니다. 하기 페이지를 확인해주세요
# https://crascit.com/2016/04/09/using-ccache-with-cmake/
find_program(CCACHE_PROGRAM ccache)

if(CCACHE_PROGRAM)
  message(STATUS "CCache Found")
  set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CCACHE_PROGRAM}")
else()
  message(STATUS "CCache Not Found")
endif()

# Git tags를 통한 버전 설정
# include(GetGitRevisionDescription)
# git_describe(GIT_VERSION --tags)
# git_commit_id(LAST_COMMIT_ID)
find_package(Git)

if(GIT_FOUND)
  message(STATUS "GIT_VERSION_STRING: ${GIT_VERSION_STRING}")
  execute_process(COMMAND ${GIT_EXECUTABLE} describe --tags WORKING_DIRECTORY ${PROJECT_SOURCE_DIR} OUTPUT_VARIABLE GIT_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)
  message(STATUS "GIT_VERSION: ${GIT_VERSION}")
  execute_process(COMMAND ${GIT_EXECUTABLE} branch --show-current WORKING_DIRECTORY ${PROJECT_SOURCE_DIR} OUTPUT_VARIABLE GIT_BRANCH OUTPUT_STRIP_TRAILING_WHITESPACE)
endif()

# 정규식을 이용한 버전 정보 추출
string(REGEX MATCH "^([A-Za-z]+)/v([0-9]+)\\.([0-9]+)\\.([0-9]+)(-([0-9]+)-g([a-z0-9]+))?" VERSIONS "${GIT_VERSION}")
set(VERSION_GROUPING_NAME ${CMAKE_MATCH_1})
set(VERSION_MAJOR ${CMAKE_MATCH_2})
set(VERSION_MINOR ${CMAKE_MATCH_3})
set(VERSION_PATCH ${CMAKE_MATCH_4})
set(VERSION_BUILD ${CMAKE_MATCH_6})
set(LAST_COMMIT_ID ${CMAKE_MATCH_7})
set(VERSION "${VERSION_GROUPING_NAME}/v${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")
set(VERSION_FULL "${VERSION}.${VERSION_BUILD}")
message(STATUS "VERSION: ${VERSION}")

# 런타임 출력 디렉토리 설정
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# fPIC용. SHARED/MODULE target에 대해 default로 on이므로 설정하지 않아도 됨.
if(NOT APPLE)
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

include(FetchContent)

set(FETCHCONTENT_UPDATES_DISCONNECTED ON)

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.14.0
)
set(gtest_build_tests OFF CACHE BOOL "Enable gtest tests" FORCE)
FetchContent_MakeAvailable(googletest)
enable_testing()

# asio 및 simplewebserver 포함 여부 결정. LMBD 배포 시에는 false
FetchContent_Declare(
  asio
  GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
  GIT_TAG asio-1-30-2
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ""
)

# # USE_STANDALONE_ASIO 가 simplewebserver cmake에서 강제로 OFF로 바뀌는 문제 해결용.
# # 낮은 버전의 Cmake에서는 문제가 생길 수 있으니 문제가 있으면 삭제.
set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
FetchContent_GetProperties(asio)

if(NOT asio_POPULATED)
  FetchContent_Populate(asio)
endif()

add_library(sr::asio INTERFACE IMPORTED)
add_dependencies(sr::asio asio)
set_property(TARGET sr::asio PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${asio_SOURCE_DIR}/asio/include)

# find_path(ASIO_PATH asio.hpp)
# if(NOT ASIO_PATH)
# message(FATAL_ERROR "Standalone Asio not found")
# else()
# target_include_directories(simplewebserver INTERFACE ${ASIO_PATH})
# endif()
FetchContent_Declare(
  simplewebserver
  GIT_REPOSITORY https://gitlab.com/eidheim/Simple-Web-Server
  GIT_TAG v3.1.1
)
FetchContent_GetProperties(simplewebserver)

set(USE_STANDALONE_ASIO ON)
set(ASIO_PATH ${asio_SOURCE_DIR}/asio/include)

if(NOT simplewebserver_POPULATED)
  FetchContent_Populate(simplewebserver)
endif()

add_subdirectory(${simplewebserver_SOURCE_DIR} ${simplewebserver_BINARY_DIR} EXCLUDE_FROM_ALL)

# add_library(sr::simplewebserver INTERFACE)
# add_dependencies(sr::simplewebserver simplewebserver)
# target_include_directories(sr::simplewebserver INTERFACE ${simplewebserver_SOURCE_DIR})

# target_compile_definitions(simplewebserver INTERFACE USE_STANDALONE_ASIO)

# # for cmake > 3.18
# # string(HEX "_ASNSCHMA_/MBR/Itsk21021-2022-06-21/*.asn -I _ASNSCHMA_/MBR/Itsk21021-2022-06-21/ -cpp11 -ber -coer -json -print -pdu all -timeopt -use-enum-types -mt -cppNs I16092" OPT_HEX)
# set(ASN_CODEC_ENABLE true)
# string(HEX "_ASNSCHMA_/MBR/Itsk21021-2022-07-08/*.asn -I _ASNSCHMA_/MBR/Itsk21021-2022-07-08/ -cpp11 -coer -json -print -timeopt -use-enum-types -mt -pdu Certificate -pdu MbSingleObservation -pdu Itsk21021MbrCommonObservations -cppNs I16092" OPT_HEX)
# set(OBJSYSASN1COER_ENABLE true)
# set(OBJSYSASN1CPER_ENABLE true)
# set(OBJSYSASN1CJSON_ENABLE true)
# set(OBJSYSASN1CBER_ENABLE true)
# set(GEN_NAME "MisbehaviorReporting")
# FetchContent_Declare(
# asn1cgen
# URL http://192.168.50.28:3100/target.tar.gz?opthex=${OPT_HEX}
# )
# FetchContent_MakeAvailable(asn1cgen)
FetchContent_Declare(json
  GIT_REPOSITORY https://github.com/nlohmann/json
  GIT_TAG v3.11.3
)
FetchContent_MakeAvailable(json)

find_package(PkgConfig REQUIRED)

# file(MAKE_DIRECTORY ${OPENSSL_INSTALL_DIR})
set(COMPILE_OPENSSL ON)

if(COMPILE_OPENSSL)
  message(STATUS "COMPILE_OPENSSL ON")
  set(OPENSSL_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl)

  if(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
    set(PROCESSOR "linux-aarch64")
  elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "linux-x86_64")
    set(PROCESSOR "linux-x86_64")
  endif()

  include(ExternalProject)
  ExternalProject_Add(
    openssl
    GIT_REPOSITORY https://github.com/openssl/openssl.git
    GIT_TAG openssl-3.3.1
    CONFIGURE_COMMAND ../openssl/Configure ${PROCESSOR} --prefix=${OPENSSL_INSTALL_DIR} --openssldir=${OPENSSL_INSTALL_DIR}
    BUILD_COMMAND make -j $(nproc)
    INSTALL_COMMAND make install
    TEST_COMMAND ""
    INSTALL_DIR "${OPENSSL_INSTALL_DIR}"
    UPDATE_DISCONNECTED TRUE
  )
  set(OPENSSL_INCLUDE_DIR ${OPENSSL_INSTALL_DIR}/include)
  file(MAKE_DIRECTORY ${OPENSSL_INCLUDE_DIR})
  set(OPENSSL_CRYPTO_LIBRARY ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.a)
  set(OPENSSL_SSL_LIBRARY ${OPENSSL_INSTALL_DIR}/lib64/libssl.a)
else()
  message(STATUS "COMPILE_OPENSSL OFF")
  find_package(OpenSSL REQUIRED)
  message(STATUS "OPENSSL_VERSION: ${OPENSSL_VERSION}")
endif()

message(STATUS "OPENSSL_INCLUDE_DIR: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OPENSSL_CRYPTO_LIBRARY: ${OPENSSL_CRYPTO_LIBRARY}")
message(STATUS "OPENSSL_SSL_LIBRARY: ${OPENSSL_SSL_LIBRARY}")

add_library(openssl::ssl STATIC IMPORTED)
set_property(TARGET openssl::ssl PROPERTY
  IMPORTED_LOCATION ${OPENSSL_SSL_LIBRARY})
set_property(TARGET openssl::ssl PROPERTY
  INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR})
add_dependencies(openssl::ssl openssl)

add_library(openssl::crypto STATIC IMPORTED)
set_property(TARGET openssl::crypto PROPERTY
  IMPORTED_LOCATION ${OPENSSL_CRYPTO_LIBRARY})
set_property(TARGET openssl::crypto PROPERTY
  INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR})
add_dependencies(openssl::crypto openssl)

# # OPENSSL

# pkg_check_modules(openssl REQUIRED IMPORTED_TARGET openssl)
# pkg_check_modules(libsasl2 REQUIRED IMPORTED_TARGET libsasl2)

# include(ExternalProject)
# set(QPID_PROTON_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/qpid-proton-prefix/install)
# file(MAKE_DIRECTORY ${QPID_PROTON_INSTALL_DIR}/include)
# ExternalProject_Add(
# qpid-proton
# GIT_REPOSITORY https://github.com/apache/qpid-proton.git
# GIT_TAG 0.39.0
# CMAKE_ARGS "-DCMAKE_INSTALL_PREFIX=${QPID_PROTON_INSTALL_DIR}" "-DBUILD_STATIC_LIBS=ON"
# TEST_COMMAND ""
# INSTALL_DIR ${QPID_PROTON_INSTALL_DIR}
# UPDATE_DISCONNECTED TRUE

# # STEP_TARGETS install
# )

# add_library(sr::qpid-proton STATIC IMPORTED)
# add_dependencies(sr::qpid-proton qpid-proton)
# set_property(TARGET sr::qpid-proton PROPERTY IMPORTED_LOCATION ${QPID_PROTON_INSTALL_DIR}/lib/libqpid-proton-cpp-static.a)
# set_property(TARGET sr::qpid-proton PROPERTY IMPORTED_LINK_INTERFACE_LIBRARIES ${QPID_PROTON_INSTALL_DIR}/lib/libqpid-proton-proactor-static.a ${QPID_PROTON_INSTALL_DIR}/lib/libqpid-proton-core-static.a ${QPID_PROTON_INSTALL_DIR}/lib/libqpid-proton-static.a)
# set_property(TARGET sr::qpid-proton PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${QPID_PROTON_INSTALL_DIR}/include)

# set(PKG_CONFIG_USE_CMAKE_PREFIX_PATH ${QPID_PROTON_INSTALL_DIR}/lib/pkgconfig)
# pkg_check_modules(QPID_PROTON REQUIRED IMPORTED_TARGET libqpid-proton-cpp)
# message(STATUS "QPID_PROTON_INCLUDE_DIRS: ${QPID_PROTON_INCLUDE_DIRS}")
# message(STATUS "QPID_PROTON_LIBRARY_DIRS: ${QPID_PROTON_LIBRARY_DIRS}")
# message(STATUS "QPID_PROTON_LIBRARIES: ${QPID_PROTON_LIBRARIES}")
# message(STATUS "QPID_PROTON_VERSION: ${QPID_PROTON_VERSION}")
# message(STATUS "QPID_PROTON_LINK_LIBRARIES: ${QPID_PROTON_LINK_LIBRARIES}")

# pkg_check_modules(Mosquitto IMPORTED_TARGET libmosquitto REQUIRED)
set(WITH_TLS OFF)
set(WITH_TLS_PSK OFF)
set(WITH_EC OFF)
set(WITH_CJSON OFF)
set(WITH_CLIENTS OFF)
set(WITH_BROKER OFF)
set(WITH_APPS OFF)
set(WITH_PLUGINS OFF)
set(DOCUMENTATION OFF)
set(WITH_STATIC_LIBRARIES ON)

# SET(WITH_THREADING OFF)
FetchContent_Declare(mosquitto
  GIT_REPOSITORY https://github.com/eclipse-mosquitto/mosquitto.git
  GIT_TAG v2.0.20
)
FetchContent_MakeAvailable(mosquitto)

#
FetchContent_Declare(fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG 10.2.0
)
FetchContent_MakeAvailable(fmt)

set(SPDLOG_FMT_EXTERNAL ON)
get_target_property(fmt_INCLUDE fmt::fmt INTERFACE_INCLUDE_DIRECTORIES)
MESSAGE(STATUS "fmt Include: ${fmt_INCLUDE}")

FetchContent_Declare(
  spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG v1.14.1
)
set(SPDLOG_BUILD_TESTS OFF CACHE BOOL "Enable spdlog tests" FORCE)
set(SPDLOG_BUILD_BENCH OFF CACHE BOOL "Enable spdlog bench" FORCE)
set(SPDLOG_BUILD_SHARED OFF CACHE BOOL "Force spdlog to static" FORCE)
FetchContent_MakeAvailable(spdlog)

if(USE_BACKWARD)
  message(STATUS "Fetching backward...")
  FetchContent_Declare(
    backward
    GIT_REPOSITORY https://github.com/bombela/backward-cpp
    GIT_TAG master
  )
  FetchContent_MakeAvailable(backward)
endif()

FetchContent_Declare(
  nanobench
  GIT_REPOSITORY https://github.com/martinus/nanobench.git
  GIT_TAG v4.3.11
  GIT_SHALLOW TRUE)
FetchContent_MakeAvailable(nanobench)

FetchContent_Declare(
  concurrentqueue
  GIT_REPOSITORY https://github.com/cameron314/concurrentqueue.git
  GIT_TAG v1.0.4
)
FetchContent_MakeAvailable(concurrentqueue)

# # OPENSSL
# find_package(OpenSSL REQUIRED)
# add_library(openssl::ssl STATIC IMPORTED)
# set_property(TARGET openssl::ssl PROPERTY
# IMPORTED_LOCATION ${OPENSSL_SSL_LIBRARY})
# set_property(TARGET openssl::ssl PROPERTY
# INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR})
# add_dependencies(openssl::ssl openssl)

# add_library(openssl::crypto STATIC IMPORTED)
# set_property(TARGET openssl::crypto PROPERTY
# IMPORTED_LOCATION ${OPENSSL_CRYPTO_LIBRARY})
# set_property(TARGET openssl::crypto PROPERTY
# INTERFACE_INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR})
# add_dependencies(openssl::crypto openssl)
# # OPENSSL
string(LENGTH "${CMAKE_SOURCE_DIR}/" SOURCE_PATH_SIZE)

configure_file(${CMAKE_SOURCE_DIR}/config.h.cmake ${CMAKE_BINARY_DIR}/config_${PROJECT_NAME}.h)

# include(Doxygen)
add_subdirectory(common)
add_subdirectory(hids)

# add_subdirectory(amqp)
# add_subdirectory(backofficekr)
