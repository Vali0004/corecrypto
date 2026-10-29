# pd interim LLM-written build glue, see README.md
# user-space corecrypto for libSystem, dyld and CommonCrypto (replaces src/Libraries/libSystem/corecrypto)
include(${CMAKE_CURRENT_LIST_DIR}/corecrypto-pd.cmake)

pd_corecrypto_sources(_pd_cc_user_sources ${PD_CORECRYPTO_COMPONENTS})

add_darwin_object_library(corecrypto_shared)
target_sources(corecrypto_shared PRIVATE ${_pd_cc_user_sources})
target_include_directories(corecrypto_shared BEFORE PUBLIC ${PD_CORECRYPTO_INCLUDE_DIRS})
target_compile_options(corecrypto_shared PRIVATE -fPIC -Wno-error -Wno-nullability-completeness)
target_link_libraries(corecrypto_shared PRIVATE
    AvailabilityHeaders
    clang_bootstrap_headers
    libc_public_headers
    pthread_common_headers
    libplatform_headers
    xnu_headers
)

add_darwin_static_library(corecrypto_static)
target_sources(corecrypto_static PRIVATE $<TARGET_OBJECTS:corecrypto_shared>)
target_include_directories(corecrypto_static BEFORE PUBLIC ${PD_CORECRYPTO_INCLUDE_DIRS})

# native build for host tools (in-tree ld64), see host-static.cmake
include(${CMAKE_CURRENT_LIST_DIR}/host-static.cmake)
