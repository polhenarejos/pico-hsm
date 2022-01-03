#define NEUG_NO_KICK      0
#define NEUG_KICK_FILLING 1

#define NEUG_PRE_LOOP 32

#define NEUG_MODE_CONDITIONED 0	/* Conditioned data.             */
#define NEUG_MODE_RAW         1	/* CRC-32 filtered sample data.  */
#define NEUG_MODE_RAW_DATA    2	/* Sample data directly.         */

extern uint8_t neug_mode;
extern uint16_t neug_err_cnt;
extern uint16_t neug_err_cnt_rc;
extern uint16_t neug_err_cnt_p64;
extern uint16_t neug_err_cnt_p4k;
extern uint16_t neug_rc_max;
extern uint16_t neug_p64_max;
extern uint16_t neug_p4k_max;

void neug_init (uint32_t *buf, uint8_t size);
uint32_t neug_get (int kick);
int neug_get_nonblock (uint32_t *p);
void neug_kick_filling (void);
void neug_flush (void);
void neug_wait_full (void);
void neug_fini (void);
void neug_mode_select (uint8_t mode);

int neug_consume_random (void (*proc) (uint32_t, int));

void crc32_rv_reset (void);
void crc32_rv_step (uint32_t v);
uint32_t crc32_rv_get (void);
uint32_t rbit (uint32_t v);
