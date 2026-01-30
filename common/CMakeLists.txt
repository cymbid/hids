MESSAGE(STATUS "==========================================")
MESSAGE(STATUS "Orchid hids common")
MESSAGE(STATUS "==========================================")

project(common)

set(CMAKE_CXX_STANDARD 17)

file(GLOB DEPS_SRC CONFIGURE_DEPENDS "src/*")
set(ALL_DEPS ${DEPS_SRC})

# 산출물 선언. 미기재시 최상위 설정에 의해 static, shared, module등 결정
# header는 기재하지 않아도 작동하나, IDE에게 알려주기 위해 적음
add_library(${PROJECT_NAME} STATIC ${ALL_DEPS})

target_include_directories(${PROJECT_NAME}
  PUBLIC
  inc
  ${CMAKE_BINARY_DIR}
  ${PROJECT_BINARY_DIR}
  ${ASIO_PATH}
  ${simplewebserver_SOURCE_DIR}
  PRIVATE
  src
)

# 의존성 설정
target_link_libraries(${PROJECT_NAME}
  PUBLIC
  nlohmann_json::nlohmann_json
  fmt::fmt
  spdlog::spdlog
  Backward::Backward

  openssl::crypto
  openssl::ssl

  # PkgConfig::openssl
  # sr::asio
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
    ${PROJECT_NAME}
  )

  add_test(NAME ${PROJECT_NAME}Test COMMAND ${PROJECT_NAME}_test)
endif()
