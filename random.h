void random_init (void);
void random_fini (void);

/* 32-byte random bytes */
const uint8_t *random_bytes_get (void);
void random_bytes_free (const uint8_t *p);

/* 8-byte salt */
void random_get_salt (uint8_t *p);

/* iterator returning a byta at a time */
int random_gen (void *arg, unsigned char *output, size_t output_len);
