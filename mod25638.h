extern const bn256 p25519[1];

void mod25638_add (bn256 *X, const bn256 *A, const bn256 *B);
void mod25638_sub (bn256 *X, const bn256 *A, const bn256 *B);
void mod25638_mul (bn256 *X, const bn256 *A, const bn256 *B);
void mod25638_sqr (bn256 *X, const bn256 *A);
void mod25519_reduce (bn256 *X);
