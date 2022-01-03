extern const bn256 p256k1;
#define P256K1 (&p256k1)

void modp256k1_add (bn256 *X, const bn256 *A, const bn256 *B);
void modp256k1_sub (bn256 *X, const bn256 *A, const bn256 *B);
void modp256k1_reduce (bn256 *X, const bn512 *A);
void modp256k1_mul (bn256 *X, const bn256 *A, const bn256 *B);
void modp256k1_sqr (bn256 *X, const bn256 *A);
void modp256k1_shift (bn256 *X, const bn256 *A, int shift);
