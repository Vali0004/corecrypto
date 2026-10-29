# pd interim LLM-written build glue, see README.md
# host_corecrypto_static for host tools (the native ld64 in nix/pkgs/toolchain/native-ld.nix), a native
# library for the build host compiled against the Darwin SDK headers
include(${CMAKE_CURRENT_LIST_DIR}/corecrypto-pd.cmake)

if(NOT TARGET host_corecrypto_static)
    pd_corecrypto_sources(_pd_cc_host_sources ${PD_CORECRYPTO_COMPONENTS})

    add_library(host_corecrypto_static STATIC ${_pd_cc_host_sources})
    target_include_directories(host_corecrypto_static BEFORE PUBLIC ${PD_CORECRYPTO_INCLUDE_DIRS})
    target_compile_options(host_corecrypto_static PRIVATE -Wno-error -Wno-nullability-completeness)

    # NIX_NATIVE_DARWIN_HEADER_FLAGS (-isysroot, -D__APPLE__ and friends) comes from native-ld.nix,
    # -nostdlibinc keeps the SDK's libc headers from layering on glibc's (__int64_t and the like differ)
    if(DEFINED ENV{NIX_NATIVE_DARWIN_HEADER_FLAGS})
        separate_arguments(_pd_cc_darwin_hdr_flags UNIX_COMMAND "$ENV{NIX_NATIVE_DARWIN_HEADER_FLAGS}")
        target_compile_options(host_corecrypto_static PRIVATE -nostdlibinc ${_pd_cc_darwin_hdr_flags})
        target_include_directories(host_corecrypto_static PRIVATE $ENV{NIX_NATIVE_DARWIN_HEADER_DIRS})
    endif()

    add_library(host_corecrypto_headers INTERFACE)
    target_include_directories(host_corecrypto_headers INTERFACE ${PD_CORECRYPTO_INCLUDE_DIRS})
    add_library(host_corecrypto_private_headers INTERFACE)
    target_include_directories(host_corecrypto_private_headers INTERFACE ${PD_CORECRYPTO_INCLUDE_DIRS})
endif()
