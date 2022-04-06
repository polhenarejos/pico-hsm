# Extra command

Pico HSM supports a customized extra command to use with different options. Since the drivers in the market do not support the following features, a raw APDU command shall be sent. 

To send a raw APDU command, `opensc-tool -s <APDU>` can be used. The `APDU` parameter is a string of hexadecimal numbers and it takes the following form:
```
8088XX00YYZZZZRR
```

It composed by the following fields:
- `80` to indicate that it is a custom vendor type command.
- `88` is the `INS` custom command.
- `XX` is the command to execute. It varies depending on the targeted command.
- `00` is the parameter of the command. At this moment, no commands support parameters.
- `YY` is the length of the data. If no data is provided, this field is absent.
- `ZZZZ` is the data to be sent. Optional. The length is variable.
- `RR` is the length of the expected response. If no response is expected, this field is absent.

## Real time clock and datetime
Pico HSM has an internal real time clock (RTC) which can track precisely the date and the time. However, when it is reset or powered down, the Pico HSM is reset to the initial datetime: 2020 January 1, 00:00:00.

### Getting the datetime
To obtain the current datetime (referenced to 00:00:00 2020/01/01), the `XX` parameter must be set to `0A`. There is no data and, thus, `YY` and `ZZZZ` are absent. The expected response is 8 bytes length.

For example, to obtain the current datetime:

```
$ opensc-tool -s 80880A0008
Using reader with a card: Free Software Initiative of Japan Gnuk
Sending: 80 88 0A 00 08 
Received (SW1=0x90, SW2=0x00):
07 E6 04 06 03 13 29 1E ......).
```

The response is composed by 8 bytes:
- The first two bytes are the current year, MSB first. Hence, `07E6h` equals to `2022`.
- 1 byte for the current month, `01h` is January and `0Ch` is December.
- 1 byte for the current day, from `01h` (1) to `1Fh` (31).
- 1 byte for the day of the week, `00h` is Sunday, `01h` is Monday, etc.
- 1 byte for the hours, from `00h` (0) to `17h` (23).
- 1 byte for the minutes, from `00h` (0) to `3Bh` (59).
- 1 byte for the seconds, from `00h` (0) to `3Bh` (59).

If the command is correctly received, `SW1=0x90` and `SW2=0x00`. Other values mean that an error has ocurred.

### Setting the datetime
To set the reference datetime, a datetime string must be provided. For example:

```
$ opensc-tool -s 80880A000807E6040603132917
Using reader with a card: Free Software Initiative of Japan Gnuk
Sending: 80 88 0A 00 08 07 E6 04 06 03 13 29 17 
Received (SW1=0x90, SW2=0x00)
```

will set the reference datetime to `Wednesday, 2022 April 6th, 19:41:23`.
