#define BN256_WORDS 8
typedef struct bn256 {
  uint32_t word[ BN256_WORDS ]; /* Little endian */
} bn256;

#define BN512_WORDS 16
typedef struct bn512 {
  uint32_t word[ BN512_WORDS ]; /* Little endian */
} bn512;

uint32_t bn256_add (bn256 *X, const bn256 *A, const bn256 *B);
uint32_t bn256_sub (bn256 *X, const bn256 *A, const bn256 *B);
uint32_t bn256_add_uint (bn256 *X, const bn256 *A, uint32_t w);
uint32_t bn256_sub_uint (bn256 *X, const bn256 *A, uint32_t w);

void bn256_mul (bn512 *X, const bn256 *A, const bn256 *B);
void bn256_sqr (bn512 *X, const bn256 *A);
uint32_t bn256_shift (bn256 *X, const bn256 *A, int shift);
int bn256_is_zero (const bn256 *X);
int bn256_is_even (const bn256 *X);
int bn256_is_ge (const bn256 *A, const bn256 *B);
int bn256_cmp (const bn256 *A, const bn256 *B);
void bn256_random (bn256 *X);
