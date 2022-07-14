# ARM Cortex-M4

This repository contains ARM Cortex-M4 code for the higher-order masked of [SABER](https://github.com/KULeuven-COSIC/SABER). The implementation is described in our paper "Higher-order masked Saber", Suparna Kundu and Jan-Pieter D’Anvers and Michiel Van Beirendonck and Angshuman Karmakar and Ingrid Verbauwhede.

## Requirements

The code in this repository includes the [pqm4](https://github.com/mupq/pqm4) framework for testing and benchmarking on the [STM32F4 Discovery board](https://www.st.com/en/evaluation-tools/stm32f4discovery.html). We refer to the documentation of [pqm4](https://github.com/mupq/pqm4) for the required prerequisites.

## Setup

After cloning or downloading this repository, it is necessary to initialize pqm4:

```bash
git submodule update --init --recursive
```

## Sources

* [HO-Masked-Saber-m4](./HO-Masked-Saber-m4/src/saber/m4-masked): Masked saber implementation

* [HO-Masked-uSaber-m4](./HO-Masked-uSaber-m4/src/saber/m4-masked): Masked usaber implementation

## Running Benchmarks and Tests

Before proceeding with the benchmarks and tests, the masked implementation should be added to [pqm4](https://github.com/mupq/pqm4):

```bash
ln -rsf ./src/saber/m4-masked ./pqm4/crypto_kem/saber/
```

or:

```bash
ln -rsf ./src/usaber/m4-masked ./pqm4/crypto_kem/saber/
```

Subsequently, apply the following patches to make pqm4 work with the masked Saber API:

```bash
cd pqm4 && git apply ../pqm4.patch
cd mupq && git apply ../../mupq.patch
```

All masked Saber tests tests can be run using:

```bash
cd pqm4
[sudo] python3 test.py saber
```

Similarly, all masked Saber benchmarks can be run using:

```bash
cd pqm4
[sudo] python3 benchmarks.py saber
```

Benchmarks can then be found in the [benchmarks](./pqm4/benchmarks) folder.

The number of shares can be changed by setting [`SABER_SHARES`](./src/saber/m4-masked/SABER_params.h).

Please note that, these implementations have been published for demonstration and benchmarking and have not gone through any leakage assessment.

## Bibliography

If you use or build upon the code in this repository, please cite our paper using our [citation key](./CITATION).

## License

Files developed in this work are released under the [MIT License](./LICENSE). [B2A.c](./src/saber/m4-masked/B2A.c) is licensed under [GNU General Public License version 2](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html).

---
Suparna Kundu and Jan-Pieter D’Anvers and Michiel Van Beirendonck and Angshuman Karmakar and Ingrid Verbauwhede.
