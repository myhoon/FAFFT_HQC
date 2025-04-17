# Improved Frobenius FFT for Code-based Cryptography on Cortex-M4

This is an implementation of HQC and BIKE paper *"Improved Frobenius FFT for Code-based Cryptography on Cortex-M4"*.

## Authors

- Myeonghoon Lee, Jihoon Jang, Suhri Kim, Seokhie Hong

## License

All implementations are in the public domain.

## Contents

- **circuitgenerator**: Implementation of optimized XOR circuit for binary matrix multiplication.  

- **crypto_kem**: Implementation of HQC and BIKE on Cortex-M4, which can be integrated into [PQM4](https://github.com/mupq/pqm4).

## Instructions for benchmarking

Our implementation targets the NUCLEO-L4R5ZI (STM32L4R5ZI) board. 

### Integrate to pqm4

First, download the pqm4 library and our library:

```bash
git clone --recursive https://github.com/mupq/pqm4.git
git clone --recursive https://github.com/myhoon/FAFFT_HQC
```

Then, copy the contents of `FAFFT_HQC/crypto_kem` into `pqm4/crypto_kem`:

```bash
cp -r FAFFT_HQC/crypto_kem/* pqm4/crypto_kem/
cd pqm4
```

From this point on, follow the standard workflow of the pqm4 framework.

## References

Our implementation is based on the following works:

- For the `circuitgenerator` component, we referred to *"Optimizing Implementations of Linear Layers"* by Zejun Xiang et al., ToSC 2020.  
  The corresponding code is available at: [https://github.com/xiangzejun/Optimizing_Implementations_of_Linear_Layers](https://github.com/xiangzejun/Optimizing_Implementations_of_Linear_Layers)

- For the BIKE implementation, we referred to *"Optimizing BIKE for the Intel Haswell and ARM Cortex-M4"* by Ming-Shing Chen et al., CHES 2021.  
  The implementation is based on the `bikel1` and `bikel3` schemes in the [PQM4 project](https://github.com/mupq/pqm4).

- For the HQC implementation, we utilized code from [PQClean](https://github.com/PQClean/PQClean) and also referenced the `bikel1` and `bikel3` implementations from the [PQM4 project](https://github.com/mupq/pqm4).