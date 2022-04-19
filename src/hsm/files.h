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

#define EF_DKEK     0x108F
#define EF_PRKDFS   0x6040
#define EF_PUKDFS   0x6041
#define EF_CDFS     0x6042
#define EF_AODFS    0x6043
#define EF_DODFS    0x6044
#define EF_SKDFS    0x6045
#define EF_DEVOPS   0x100E

extern file_t *file_pin1;
extern file_t *file_retries_pin1;
extern file_t *file_sopin;
extern file_t *file_retries_sopin;

#endif