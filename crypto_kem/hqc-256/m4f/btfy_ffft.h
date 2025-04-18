// Implemented by Ming-Shing Chen, Tung Chou and Markus Krausz.
// 
// Modification :  Myeonghoon Lee and Jihoon Jang
//
// public domain

#ifndef _BTFY_FFFT_H_
#define _BTFY_FFFT_H_

#include "stdint.h"


void btfy_32768( uint32_t * poly );

void ibtfy_32768( uint32_t * poly );


void btfy_65536( uint32_t * poly );

void ibtfy_65536( uint32_t * poly );

void btfy_131072(uint32_t * poly);

void ibtfy_131072(uint32_t * poly);


#endif
