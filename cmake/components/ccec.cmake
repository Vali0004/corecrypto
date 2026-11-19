# Security.framework only: the curve arithmetic is OpenSSL libcrypto's, which only Security links
set(CORECRYPTO_ccec_PUBLIC_HEADERS
    corecrypto/ccec.h
    corecrypto/ccec_priv.h
    corecrypto/ccecies.h
    )

set(CORECRYPTO_ccec_SOURCES
    ccec_pd_security.c
)
