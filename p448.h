#define N_REDUNDANT_LIMBS 16
typedef struct p448_t
{
  uint32_t limb[N_REDUNDANT_LIMBS];
} p448_t;

void p448_add (p448_t *x, const p448_t *a, const p448_t *b);
void p448_sub (p448_t *x, const p448_t *a, const p448_t *b);
void p448_mul (p448_t *__restrict__ x, const p448_t *a, const p448_t *b);
void p448_mul_39081 (p448_t *x, const p448_t *a);
void p448_sqr (p448_t *__restrict__ c, const p448_t *a);
void p448_inv (p448_t *__restrict__ x, const p448_t *a);
void p448_serialize (uint8_t serial[56], const p448_t *x);
void p448_deserialize (p448_t *x, const uint8_t serial[56]);
void p448_strong_reduce (p448_t *a);
