MESSAGE(STATUS "==========================================")
MESSAGE(STATUS "Orchid hids")
MESSAGE(STATUS "==========================================")

project(hids)

set(CMAKE_CXX_STANDARD 17)

FetchContent_Declare(
  cxxopts
  GIT_REPOSITORY https://github.com/jarro2783/cxxopts
  GIT_TAG v3.2.1
)
FetchContent_MakeAvailable(cxxopts)

# FetchContent_GetProperties(cxxopts)
# if(NOT cxxopts_POPULATED)
# FetchContent_Populate(cxxopts)
# add_subdirectory(${cxxopts_SOURCE_DIR} ${cxxopts_BINARY_DIR} EXCLUDE_FROM_ALL)
# endif()

# Corrosion : Rust CMake 통합 도구
FetchContent_Declare(
  Corrosion
  GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
  GIT_TAG v0.6.1
)
FetchContent_MakeAvailable(Corrosion)

# YaraX 라이브러리 설정
FetchContent_Declare(
  yara_x
  GIT_REPOSITORY https://github.com/VirusTotal/yara-x.git
  GIT_TAG v1.11.0
)
FetchContent_MakeAvailable(yara_x)

# [Step 3] 다운로드된 소스의 Cargo.toml을 Corrosion에 등록
# my_rust_git_lib_SOURCE_DIR은 FetchContent가 설정해주는 변수입니다.
message(STATUS "yara_x_SOURCE_DIR: ${yara_x_SOURCE_DIR}")
corrosion_import_crate(MANIFEST_PATH "${yara_x_SOURCE_DIR}/Cargo.toml")

file(GLOB DEPS_SRC CONFIGURE_DEPENDS "src/*")
set(ALL_DEPS ${DEPS_SRC})

# 산출물 선언. 미기재시 최상위 설정에 의해 static, shared, module등 결정
# header는 기재하지 않아도 작동하나, IDE에게 알려주기 위해 적음
add_library(${PROJECT_NAME}Lib STATIC ${ALL_DEPS})

target_include_directories(${PROJECT_NAME}Lib
  PUBLIC
  inc
  ${CMAKE_BINARY_DIR}
  ${PROJECT_BINARY_DIR}

  ${mosquitto_SOURCE_DIR}/lib ${mosquitto_SOURCE_DIR}/lib/cpp
  ${mosquitto_SOURCE_DIR}/include
  "${yara_x_SOURCE_DIR}/capi/include"
  PRIVATE
  src
)

get_target_property(mosquittopp_static_INCLUDE mosquittopp_static INTERFACE_INCLUDE_DIRECTORIES)
MESSAGE(STATUS "mosquittopp_static Include: ${mosquittopp_static_INCLUDE}")
get_target_property(libmosquitto_INCLUDE libmosquitto INTERFACE_INCLUDE_DIRECTORIES)
MESSAGE(STATUS "libmosquitto Include: ${libmosquitto_INCLUDE}")

# 의존성 설정
target_link_libraries(${PROJECT_NAME}Lib
  PUBLIC

  cxxopts
  spdlog::spdlog

  # mosquitto_static
  mosquittopp_static
  libmosquitto
  common

  PRIVATE
  yara_x
  yara_x_capi
)

add_executable(${PROJECT_NAME}
  main_function.cpp
)
target_include_directories(${PROJECT_NAME}
  PUBLIC

  PRIVATE
  src
)
target_link_libraries(${PROJECT_NAME} PRIVATE
  ${PROJECT_NAME}Lib
)

# set(CMAKE_INSTALL_DEFAULT_COMPONENT_NAME "TrafficInjector")

# install(TARGETS ${PROJECT_NAME}
# RUNTIME
# DESTINATION bin
# COMPONENT TrafficInjector
# )

# install(TARGETS
# LIBRARY
# DESTINATION lib
# COMPONENT TrafficInjector
# )

# install(TARGETS
# ARCHIVE
# DESTINATION etc
# COMPONENT conf
# )

# install(TARGETS
# PUBLIC_HEADER
# DESTINATION etc
# COMPONENT bin
# )

# 테스트 설정
if(BUILD_TESTING)
  file(GLOB DEPS CONFIGURE_DEPENDS "gtest/*")

  add_executable(${PROJECT_NAME}_test ${DEPS})
  target_include_directories(${PROJECT_NAME}_test
    PRIVATE
    gtest
    src
  )

  # MESSAGE(STATUS "DEPS: ${DEPS}")
  target_link_libraries(${PROJECT_NAME}_test
    PRIVATE
    gtest
    ${PROJECT_NAME}Lib
  )

  add_test(NAME ${PROJECT_NAME}Test COMMAND ${PROJECT_NAME}_test)
endif()
