# pd interim LLM-written build glue, see README.md
# PureDarwin build glue: PD's tree includes this file and gets the corecrypto targets
# corecrypto_shared, corecrypto_static, host_corecrypto_static (user space) and corecrypto.kext.
# PD_CORECRYPTO_INCLUDE_DIRS lists every public header directory.

set(PD_CORECRYPTO_ROOT ${CMAKE_CURRENT_LIST_DIR}/..)

set(PD_CORECRYPTO_COMPONENTS
    cc ccaes ccansikdf ccasn1 ccblowfish cccast ccchacha20poly1305 cccmac ccdes ccdigest
    ccdrbg cchkdf cchmac ccmd2 ccmd4 ccmd5 ccmode ccn ccnistkdf ccpad ccpbkdf2
    ccrc2 ccrc4 ccripemd ccrng ccsha1 ccsha2 ccwrap)

# the power-on self tests only run in the kext
set(PD_CORECRYPTO_KERNEL_COMPONENTS ${PD_CORECRYPTO_COMPONENTS} cckprng ccpost)

set(PD_CORECRYPTO_INCLUDE_DIRS "")
# ccrsa and cczp only bring headers, register_crypto.h declares the rsa hooks with their types
foreach(component IN LISTS PD_CORECRYPTO_KERNEL_COMPONENTS ITEMS ccrsa cczp)
    list(APPEND PD_CORECRYPTO_INCLUDE_DIRS ${PD_CORECRYPTO_ROOT}/${component}/include)
endforeach()
set(PD_CORECRYPTO_INCLUDE_DIRS ${PD_CORECRYPTO_INCLUDE_DIRS} CACHE INTERNAL "corecrypto public headers")

function(pd_corecrypto_sources out)
    set(result "")
    foreach(component IN LISTS ARGN)
        include(${PD_CORECRYPTO_ROOT}/cmake/components/${component}.cmake)
        foreach(file IN LISTS CORECRYPTO_${component}_SOURCES)
            list(APPEND result ${PD_CORECRYPTO_ROOT}/${component}/src/${file})
        endforeach()
    endforeach()
    set(${out} ${result} PARENT_SCOPE)
endfunction()
