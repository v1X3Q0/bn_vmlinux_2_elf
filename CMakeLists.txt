cmake_minimum_required(VERSION 3.20.0)


if (NOT DEFINED ANDROID_TOOL_BASE)
    message(WARNING "need ANDROID_TOOL_BASE")
    set(ANDROID_TOOL_BASE ${CMAKE_CURRENT_SOURCE_DIR})

    set(NOLIVE 1)
    add_subdirectory(${ANDROID_TOOL_BASE}/linux/helpers/tools/parseandroidkernrel)
    add_subdirectory(${ANDROID_TOOL_BASE}/common/kern_img)
endif()

add_subdirectory(ki_to_vmlinux)