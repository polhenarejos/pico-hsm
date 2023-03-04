"""
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
"""

import pytest
import math
from collections import Counter

def mean(x):
    sum = 0
    for i in x:
        sum += i
    return sum/len(x)

def var(x):
    sum = 0
    m = mean(x)
    for i in x:
        sum += (i-m)**2
    return sum/len(x)

@pytest.mark.parametrize(
    "length", [1, 256, 1024]
)
def test_challenge(device, length):
    data = device.get_challenge(length)
    assert(len(data) == length)

def test_randomness(device):
    data = []
    N = 1000
    for k2 in range(N):
        data += device.get_challenge(1024)

    _, values = zip(*Counter(data).items())

    nm = mean(values)/(N*1024/256)
    sm = math.sqrt(var(values))/mean(values)

    assert(0.99 <= nm <= 1.01)
    assert(sm <= 0.02)

