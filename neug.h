#define NEUG_NO_KICK      0
#define NEUG_KICK_FILLING 1

#define NEUG_PRE_LOOP 32

#define NEUG_MODE_CONDITIONED 0	/* Conditioned data.             */
#define NEUG_MODE_RAW         1	/* CRC-32 filtered sample data.  */
#define NEUG_MODE_RAW_DATA    2	/* Sample data directly.         */

void neug_init (uint32_t *buf, uint8_t size);
uint32_t neug_get (int kick);
void neug_flush (void);
void neug_wait_full (void);
void neug_fini (void);
