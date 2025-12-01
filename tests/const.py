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

from binascii import unhexlify

DEFAULT_DKEK = [0x1] * 32

TERM_CERT = unhexlify('7f2181e57f4e819e5f290100421045535049434f48534d445630303030327f494f060a04007f000702020202038641043400e4f42ea8b78b2ab58d24c8297a4b1c13a73a631b531e58d0efb60d70dd6666c8fce4130e9b15ffa4ad29708d32764ac4b0cc0e5301898522f4c735f5a90d5f201045535049434f48534d54524c524134437f4c0e060904007f0007030102025301005f25060205010102085f24060206010102085f3740569f6fe91796f95fa77ecdb680468417eed7b4e00ccc2e091a6b56389213f913c4cf91da96fbcb12d363fead30a5598f737975d58b5170b7f45e9e87ec546883')
DICA_CERT = unhexlify('7f2181e97f4e81a25f290100421045535049434f48534d434130303030327f494f060a04007f00070202020203864104e66b473ec328caf39eaed840f9c7a4ba237e1dd19004861fa3f4f134bd2d5ea5f71c6c2e6321add4c8a7793ba41119c5783f48a5d9dfc0898d9ae9e7b14da8d65f201045535049434f48534d445630303030327f4c12060904007f000703010202530580000000045f25060205000400065f24060206000400065f3740a645594c6c338cd6bda6cad039cee54fd822b1011c0af1e4e3a2a6d03d43bdbb8be68a66a8757e7b1f963589bdd80d8e65de5055b722609041ec63f0498ddc8b')
