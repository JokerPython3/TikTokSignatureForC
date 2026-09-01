cmake_minimum_required(VERSION 3.14)
project(TikTokSignatureForC VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(TIKTOK_BUILD_TESTS "Build tests" ON)
option(TIKTOK_BUILD_EXAMPLE "Build example" ON)

add_library(tiktoksignature STATIC
    src/sm3.c
    src/simon.c
    src/protobuf.c
    src/crypto_helpers.c
    src/url_encode.c
    src/argus.c
    src/ladon.c
    src/gorgon.c
    src/signer.c
    src/mini_json.c
)

target_include_directories(tiktoksignature
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_options(tiktoksignature PRIVATE
    -Wall -Wextra -Wpedantic
)

find_package(OpenSSL REQUIRED)
target_link_libraries(tiktoksignature PUBLIC OpenSSL::Crypto)

if(TIKTOK_BUILD_TESTS)
    enable_testing()
    add_executable(test_all tests/test_all.c)
    target_link_libraries(test_all PRIVATE tiktoksignature)
    target_include_directories(test_all PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    )
    target_compile_options(test_all PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME tiktok_tests COMMAND test_all ${CMAKE_CURRENT_SOURCE_DIR}/testdata)
endif()

if(TIKTOK_BUILD_EXAMPLE)
    find_package(CURL)
    if(CURL_FOUND)
        add_executable(example examples/Example.c)
        target_link_libraries(example PRIVATE tiktoksignature CURL::libcurl)
        target_include_directories(example PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
        target_compile_options(example PRIVATE -Wall -Wextra -Wpedantic)
    else()
        message(WARNING "libcurl not found, skipping example build")
    endif()
endif()
