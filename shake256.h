#include <stdint.h>

struct shake_context {
  uint64_t state[25];
  uint32_t index;
};
typedef struct shake_context shake_context;

void shake256_start (struct shake_context *shake);
void shake256_update (struct shake_context *shake,
		      const unsigned char *src, unsigned int size);
void shake256_finish (struct shake_context *shake,
		      unsigned char *dst, unsigned int size);
