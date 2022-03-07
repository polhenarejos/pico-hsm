/**
 * @brief	Jacobian projective coordinates
 */
typedef struct
{
  bn256 x[1];
  bn256 y[1];
  bn256 z[1];
} jpc;

void jpc_double_p256k1 (jpc *X, const jpc *A);
void jpc_add_ac_p256k1 (jpc *X, const jpc *A, const ac *B);
void jpc_add_ac_signed_p256k1 (jpc *X, const jpc *A, const ac *B, int minus);
int jpc_to_ac_p256k1 (ac *X, const jpc *A);
