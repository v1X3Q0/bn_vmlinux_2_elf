project(ki_to_vmlinux)
add_executable(${PROJECT_NAME} main.cpp plugin_load.cpp ki_to_vmlinux.cpp)

if (NOT DEFINED ANDROID_TOOL_BASE)
    message(WARNING "need ANDROID_TOOL_BASE")
    set(ANDROID_TOOL_BASE ${CMAKE_CURRENT_SOURCE_DIR})
endif()

set(INCLUDE_DIRS
    ${ANDROID_TOOL_BASE}/common/c_reginst
    ${ANDROID_TOOL_BASE}/common/local_util
    ${ANDROID_TOOL_BASE}/common/bgrep_c
    ../parseAndKern
    ${ANDROID_TOOL_BASE}/linux/rwDrv/include
    ${ANDROID_TOOL_BASE}/common/kern_img/linux
    ${ANDROID_TOOL_BASE}/common/kern_img/common
    )

set(LINK_LIBRARIES
    parseAndKern
    # kern_linux
    kernel_block
    bgrep_e localUtil)

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    list(APPEND INCLUDE_DIRS /usr/include/json-c)
    list(APPEND LINK_LIBRARIES json-c)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    list(APPEND INCLUDE_DIRS /usr/local/include/json-c ${ANDROID_TOOL_BASE}/common/local_util/linux_compat)
    target_link_directories(${PROJECT_NAME} PRIVATE /usr/local/lib/)
    list(APPEND LINK_LIBRARIES json-c)
endif()

# for now i've added these kernel dependencies, considering splitting them.
# target_link_libraries(ki_to_vmlinux PRIVATE krw_util targkrw drv_krw)
target_include_directories(${PROJECT_NAME} PRIVATE ${INCLUDE_DIRS})

# for the kernel image parsing
target_link_libraries(${PROJECT_NAME} PRIVATE ${LINK_LIBRARIES})
