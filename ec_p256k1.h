int compute_kP_p256k1 (ac *X, const bn256 *K, const ac *P);
int compute_kG_p256k1 (ac *X, const bn256 *K);
void ecdsa_p256k1 (bn256 *r, bn256 *s, const bn256 *z, const bn256 *d);
int check_secret_p256k1 (const bn256 *q, bn256 *d1);
