#ifndef _PARAMETERS_H_
#define _PARAMETERS_H_

#include "api.h"

#define SECURITYLEVEL 5
#define _M4_ASM_

#if SECURITYLEVEL==1
#define HQC128
#elif SECURITYLEVEL==3
#define HQC192
#elif SECURITYLEVEL==5
#define HQC256
#endif


#ifdef HQC128
#define N 17669
#define PARAM_N1                              46
#define PARAM_N2                              384
#define PARAM_N1N2                            17664
#define PARAM_OMEGA                           66
#define PARAM_OMEGA_E                         75
#define PARAM_OMEGA_R                         75
#define FFT_N 65536
#define HALF_N 32768
#define PARAM_DELTA                           15
#define PARAM_M                               8
#define PARAM_GF_POLY                         0x11D
#define PARAM_GF_POLY_WT                      5
#define PARAM_GF_POLY_M2                        4
#define PARAM_GF_MUL_ORDER                    255
#define PARAM_K                               16
#define PARAM_G                               31
#define PARAM_FFT                             4
#define RS_POLY_COEFS 89,69,153,116,176,117,111,75,73,233,242,233,65,210,21,139,103,173,67,118,105,210,174,110,74,69,228,82,255,181,1

#define RED_MASK                              0x1f
#define SHAKE256_512_BYTES                    64
#define SEED_BYTES                            40
#define SALT_SIZE_BYTES                       16
#elif defined(HQC192)
#define N 35851
#define PARAM_N1                                56
#define PARAM_N2                                640
#define PARAM_N1N2                              35840
#define PARAM_OMEGA                             100
#define PARAM_OMEGA_E                           114
#define PARAM_OMEGA_R                           114
#define FFT_N 131072
#define HALF_N 65536
#define PARAM_DELTA                             16
#define PARAM_M                                 8
#define PARAM_GF_POLY                           0x11D
#define PARAM_GF_POLY_WT                      5
#define PARAM_GF_POLY_M2                        4
#define PARAM_GF_MUL_ORDER                      255
#define PARAM_K                                 24
#define PARAM_G                                 33
#define PARAM_FFT                               5
#define RS_POLY_COEFS 45,216,239,24,253,104,27,40,107,50,163,210,227,134,224,158,119,13,158,1,238,164,82,43,15,232,246,142,50,189,29,232,1

#define RED_MASK                                0x7ff
#define SHAKE256_512_BYTES                    64
#define SEED_BYTES                              40
#define SALT_SIZE_BYTES                       16
#elif defined(HQC256)
#define N 57637
#define PARAM_N1                                90
#define PARAM_N2                                640
#define PARAM_N1N2                              57600
#define PARAM_OMEGA                             131
#define PARAM_OMEGA_E                           149
#define PARAM_OMEGA_R                           149
#define FFT_N 131072
#define HALF_N 65536
#define PARAM_DELTA                             29
#define PARAM_M                                 8
#define PARAM_GF_POLY                           0x11D
#define PARAM_GF_POLY_WT                      5
#define PARAM_GF_POLY_M2                        4
#define PARAM_GF_MUL_ORDER                      255
#define PARAM_K                                 32
#define PARAM_G                                 59
#define PARAM_FFT                               5
#define RS_POLY_COEFS 49,167,49,39,200,121,124,91,240,63,148,71,150,123,87,101,32,215,159,71,201,115,97,210,186,183,141,217,123,12,31,243,180,219,152,239,99,141,4,246,191,144,8,232,47,27,141,178,130,64,124,47,39,188,216,48,199,187,1

#define RED_MASK                                0x1fffffffff
#define SHAKE256_512_BYTES                    64
#define SEED_BYTES                              40
#define SALT_SIZE_BYTES                       16
#else
#define ERROR
#endif
#define VEC_N_SIZE_64 (N+63)/64
#define FFT_N_64 FFT_N/64
#define HALF_N_64 HALF_N/64
#define VEC_N_SIZE_32 (N+31)/32

#define CEIL_DIVIDE(a, b)  (((a)+(b)-1)/(b))

#define PARAM_N N

#define SECRET_KEY_BYTES                      CRYPTO_SECRETKEYBYTES
#define PUBLIC_KEY_BYTES                      CRYPTO_PUBLICKEYBYTES
#define SHARED_SECRET_BYTES                   CRYPTO_BYTES
#define CIPHERTEXT_BYTES                      CRYPTO_CIPHERTEXTBYTES

#define VEC_N_SIZE_BYTES                      (N+7)/8
#define VEC_K_SIZE_BYTES                      PARAM_K
#define VEC_N1_SIZE_BYTES                     PARAM_N1
#define VEC_N1N2_SIZE_BYTES                   (PARAM_N1N2+7)/8

#define VEC_K_SIZE_64                         CEIL_DIVIDE(PARAM_K, 8)
#define VEC_N1_SIZE_64                        CEIL_DIVIDE(PARAM_N1, 8)
#define VEC_N1N2_SIZE_64                      CEIL_DIVIDE(PARAM_N1N2, 64)

#endif
