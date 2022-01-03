#define SHA512_DIGEST_SIZE  64
#define SHA512_BLOCK_SIZE   128

typedef struct
{
  uint64_t total[2];
  uint64_t state[8];
  uint64_t wbuf[16];
} sha512_context;

void sha512 (const unsigned char *input, unsigned int ilen,
	     unsigned char output[64]);
void sha512_start (sha512_context *ctx);
void sha512_finish (sha512_context *ctx, unsigned char output[64]);
void sha512_update (sha512_context *ctx, const unsigned char *input,
		    unsigned int ilen);
void sha512_process (sha512_context *ctx);
