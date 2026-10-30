# NEORV32 and Cryptography Experiments

This repository contains NEORV32 code and cryptography experiments for RISC-V. This README credits work and code by others that the repository uses or references. Citing a paper that describes an **algorithm** does not imply that the implementation here was copied from that paper.

## External code and projects

| Component | Author / source | Location and use in this repository | License / notes |
| --- | --- | --- | --- |
| [NEORV32](https://github.com/stnolting/neorv32) | Stephan Nolting and NEORV32 contributors | RISC-V processor platform, RTL, software libraries, simulation, and documentation in `rtl/`, `sw/`, `sim/`, and `docs/` | BSD 3-Clause; see `LICENSE` and the copyright notices in individual files. The project's name is **NEORV32**. |
| [tiny-AES-c](https://github.com/kokke/tiny-AES-c) | kokke and contributors | `tiny-AES-c/`; `sw/example/hello_world/makefile` compiles `tiny-AES-c/aes.c` as an AES baseline | The Unlicense; see `tiny-AES-c/unlicense.txt`. |
| [CoreMark](https://github.com/eembc/coremark) | Embedded Microprocessor Benchmark Consortium (EEMBC) | `sw/example/coremark/` | Apache License 2.0, as stated in the source file headers. |
| [Petit FatFs](https://elm-chan.org/fsw/ff/pf/) | ChaN | `sw/bootloader/petit_fatfs/` | The author's terms are included in `pff.c` and `pff.h`. |
| [Dhrystone](https://github.com/sifive/benchmark-dhrystone) | Reinhold P. Weicker; translated to C by Rick Richardson, obtained via the SiFive repository | `sw/example/dhrystone/` | `sw/example/dhrystone/LICENSE` states that no explicit license is defined. |
| [RISC-V Architectural Tests](https://github.com/riscv-non-isa/riscv-arch-test) | RISC-V community | Submodule declared in `.gitmodules`; NEORV32 configuration in `sw/riscv-arch-test/plugins/` | Consult the license of the test suite version in use. |
| [LiteX](https://github.com/enjoy-digital/litex) | Enjoy-Digital and contributors | `rtl/system_integration/neorv32_litex_core_complex.vhd` credits the LiteX integration source | See the file header and the upstream project's license. |
| [neoTRNG](https://github.com/stnolting/neoTRNG) | Stephan Nolting | `rtl/core/neorv32_trng.vhd` states that its design is based on neoTRNG | See the copyright notice in the RTL file. |
| [Oryx Embedded Common](https://github.com/Oryx-Embedded/Common/blob/master/date_time.c) | Oryx Embedded SARL | Two date and time conversion functions in `sw/lib/source/neorv32_aux.c` credit this source | Their headers specify `GPL-2.0-or-later`. |
| Magma / GOST 28147-89 reference code | Vlasta Vesely and Colin Plumb; [original GOST source](https://www.schneier.com/sccd/GOST-PLU.ZIP) | Root-level `magma.c`, separate from the experimental implementation in `sw/example/hello_world/magma.c` | The root-level file specifies GPL version 2 or later for subsequent changes. |
| [Kuznyechik reference code](https://github.com/mjosaarinen/kuznechik/blob/master/kuznechik_128bit.c) | Markku-Juhani O. Saarinen and Vlasta Vesely | Root-level `kuznyechik.c` | The file header specifies GPL version 2 or later. |

The terms attached to these individual files still apply; the root-level `LICENSE` does not replace licenses for external code.

## Referenced algorithms and designs

| Work | Where it is referenced |
| --- | --- |
| NIST, [FIPS 197 — Advanced Encryption Standard (AES)](https://csrc.nist.gov/pubs/fips/197/final) and [SP 800-38A — Recommendation for Block Cipher Modes of Operation](https://csrc.nist.gov/pubs/sp/800/38/a/final) | AES implementations in `sw/example/hello_world/` and test vectors. These are algorithm specifications and test vectors, not code licenses. |
| Joan Boyar and René Peralta, [“A New Combinational Logic Minimization Technique with Applications to Cryptology”](https://eprint.iacr.org/2009/191.pdf) | The bit-sliced AES S-box circuit discussed in `sw/example/hello_world/aes_bs.c`. |
| Daniel J. Bernstein, [“ChaCha, a Variant of Salsa20”](https://cr.yp.to/chacha/chacha-20080120.pdf) | `sw/example/hello_world/chacha.c` and `chacha.h`. |
| Deukjo Hong et al., [“LEA: A 128-Bit Block Cipher for Fast Encryption on Common Processors”](https://doi.org/10.1007/978-3-319-05149-9_1) | `sw/example/hello_world/lea.c` and `lea.h`. |
| Ray Beaulieu et al., [“The SIMON and SPECK Families of Lightweight Block Ciphers”](https://eprint.iacr.org/2013/404.pdf) | `simon.c`, `speck.c`, `speck_fast.c`, and `speck128.c` in `sw/example/hello_world/`. |
| Andrey Bogdanov et al., [“PRESENT: An Ultra-Lightweight Block Cipher”](https://www.iacr.org/archive/ches2007/47270450/47270450.pdf) | `sw/example/hello_world/present.c` and `present.h`. |
| Julia Borghoff et al., [“PRINCE — A Low-Latency Block Cipher for Pervasive Computing Applications”](https://eprint.iacr.org/2012/529.pdf) | `sw/example/hello_world/prince.c` and `prince.h`. |

The optimized MKV-128 implementations in `sw/example/hello_world/` identify the baseline code in `MKV128_8bit/` and `MKV128_32bit/`. The repository does not provide enough information to identify MKV-128's original authors or publication, so this README does not assign an unverified external source.
