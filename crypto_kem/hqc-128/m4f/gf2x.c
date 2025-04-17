#include "gf2x.h"
#include "parameters.h"
#include <stddef.h>
#include <stdint.h>
#include "reduce.h"
#include "gfmul_fft.h"
#include <string.h>

/**
 * @brief Multiply two polynomials modulo \f$ X^n - 1\f$.
 *
 * This functions multiplies polynomials <b>v1</b> and <b>v2</b>.
 * The multiplication is done modulo \f$ X^n - 1\f$.
 *
 * @param[out] o Product of <b>v1</b> and <b>v2</b>
 * @param[in] v1 Pointer to the first polynomial
 * @param[in] v2 Pointer to the second polynomial
 */
void PQCLEAN_HQC128_CLEAN_vect_mul(uint64_t *o, const uint64_t *v1, const uint64_t *v2) {

	uint32_t o_u32[FFT_N / 32] = { 0 };

	bmul2_4096_to_8192((uint8_t*)o_u32, (uint8_t*)v1, (uint8_t*)v2);
	reduce((uint32_t*)o, (uint32_t*)o_u32);

}
