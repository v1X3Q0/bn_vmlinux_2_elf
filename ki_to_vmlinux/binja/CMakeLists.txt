project(binja_k2v)

set(CMAKE_CXX_STANDARD 17)

if (NOT DEFINED BN_API_PATH)
    message(FATAL_ERROR "need BN_API_PATH")
endif()

if (NOT EXISTS ${BN_API_PATH})
    message(FATAL_ERROR "bad path provided BN_API_PATH=${BN_API_PATH}")
endif()

# set(HEADLESS 1)
find_path(
        BN_API_PATH
        NAMES binaryninjaapi.h
        # List of paths to search for the clone of the api
        HINTS ../.. binaryninjaapi $ENV{BN_API_PATH}
        REQUIRED
)

add_subdirectory(${BN_API_PATH} api)

add_library(${PROJECT_NAME} SHARED binja_main.cpp)

target_include_directories(${PROJECT_NAME} PRIVATE ${BN_API_PATH})

target_link_libraries(${PROJECT_NAME} PUBLIC binaryninjaapi)

bn_install_plugin(${PROJECT_NAME})
