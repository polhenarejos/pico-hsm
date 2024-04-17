/*
 * This file is part of the Pico HSM distribution (https://github.com/polhenarejos/pico-hsm).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */


#ifndef _FILES_H_
#define _FILES_H_

#include "file.h"

#define EF_DEVOPS       0x100E
#define EF_MKEK         0x100A
#define EF_MKEK_SO      0x100B
#define EF_XKEK         0x1070
#define EF_PIN1         0x1081
#define EF_PIN1_MAX_RETRIES 0x1082
#define EF_PIN1_RETRIES 0x1083
#define EF_SOPIN        0x1088
#define EF_SOPIN_MAX_RETRIES 0x1089
#define EF_SOPIN_RETRIES 0x108A
#define EF_DKEK         0x1090
#define EF_KEY_DOMAIN   0x10A0
#define EF_PUKAUT       0x10C0
#define EF_PUK          0x10D0
#define EF_MASTER_SEED  0x1110
#define EF_PRKDFS       0x6040
#define EF_PUKDFS       0x6041
#define EF_CDFS         0x6042
#define EF_AODFS        0x6043
#define EF_DODFS        0x6044
#define EF_SKDFS        0x6045

#define EF_KEY_DEV      0xCC00
#define EF_PRKD_DEV     0xC400
#define EF_EE_DEV       0xCE00

#define EF_TERMCA       0x2F02
#define EF_TOKENINFO    0x2F03
#define EF_STATICTOKEN  0xCB00

extern file_t *file_pin1;
extern file_t *file_retries_pin1;
extern file_t *file_sopin;
extern file_t *file_retries_sopin;

#endif
