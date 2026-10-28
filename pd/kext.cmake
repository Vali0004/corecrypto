# pd interim LLM-written build glue, see README.md
# corecrypto.kext (replaces src/Kernel/Extensions/corecrypto), same bundle id and install path as before
include(${CMAKE_CURRENT_LIST_DIR}/corecrypto-pd.cmake)

pd_corecrypto_sources(_pd_cc_kext_sources ${PD_CORECRYPTO_KERNEL_COMPONENTS})

add_kext_bundle(corecrypto.kext INFO_PLIST ${CMAKE_CURRENT_LIST_DIR}/kext/Info.plist KERNEL_PRIVATE
    BUNDLE_IDENTIFIER com.apple.kec.corecrypto BUNDLE_VERSION 1.0d1
    MAIN_FUNCTION corecrypto_start ANTIMAIN_FUNCTION corecrypto_stop
)
set_property(TARGET corecrypto.kext PROPERTY OUTPUT_NAME corecrypto)

target_sources(corecrypto.kext PRIVATE
    ${_pd_cc_kext_sources}
    ${PD_CORECRYPTO_ROOT}/corecrypto_kext/main.c
)
# neo's headers must win over xnu's EXTERNAL_HEADERS copies
target_include_directories(corecrypto.kext BEFORE PRIVATE ${PD_CORECRYPTO_INCLUDE_DIRS} ${PD_CORECRYPTO_ROOT}/corecrypto_kext)
target_compile_options(corecrypto.kext PRIVATE -Wno-error -Wno-nullability-completeness)
target_link_libraries(corecrypto.kext PRIVATE xnu_kernel_private_headers)
install(TARGETS corecrypto.kext DESTINATION System/Library/Extensions COMPONENT BaseSystem)
