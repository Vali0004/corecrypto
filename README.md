# corecrypto (PureDarwin interim fork)

This is PureDarwin's interim fork of NeoDarwin's corecrypto. It is not NeoDarwin's corecrypto, and it must never be upstreamed.

## Why this must never be upstreamed

The changes in this fork were written with an LLM. NeoDarwin does not accept AI-generated contributions, so none of this work may be offered to NeoDarwin, merged into NeoDarwin's repository, or presented as NeoDarwin code. Upstream is https://github.com/NeoDarwinOS/corecrypto, and anything taken from there should come from upstream directly, not from this fork.

## Not secure

These changes are experimental. They have not been audited, fuzzed or checked for side channels, and they must not be relied on to protect anything. They exist so that PureDarwin can boot and run its software while a properly reviewed implementation is written.

## What it is for

PureDarwin uses this fork as an external component, in place of the GPL corecrypto it carried before, for libSystem's symmetric primitives and for corecrypto.kext, including the kext's RSA PKCS#1 v1.5 signature verification (RFC 8017). It is temporary, and parts of it will be rewritten by hand. The changes are tested against known-answer vectors from the RFCs, FIPS 180-4, the NIST SP 800 series and CAVP, in cctest/pd, and the RSA verifier against Wycheproof and CAVP 186-3 SigVer15 vectors.

## Licence

Like upstream, this fork is licensed under the Mozilla Public License 2.0, see LICENSE. Upstream's own README, including its acknowledgements for the code adapted from LibTomCrypt, is at https://github.com/NeoDarwinOS/corecrypto.
