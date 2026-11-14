#!/usr/bin/env python3
"""
lcd1602_i2c.py
------------------------------------------------------------
Minimal driver for a 16x2 character LCD behind a PCF8574 I2C
backpack (the common "blue board" I2C 1602 module), written for
smbus2 on a Raspberry Pi.

This project wires its two LCD1602 status displays to the gateway's
I2C bus alongside the two INA219 current sensors (see Section 3.8 /
Figure 3.1 of the paper). The INA219 sensors occupy addresses 0x40
and 0x41; the two LCD backpacks must be at two OTHER, distinct
addresses. 0x27 and 0x3F are the common factory-default addresses
for two PCF8574-based backpacks straight out of the box -- CONFIRM
your actual addresses before running anything that depends on this
file:

    i2cdetect -y 1

and update LCD1_ADDR / LCD2_ADDR in gateway_protocol_v7_lcd_dashboard.py
to match what you see.

Requires: pip install smbus2
"""

import time
from smbus2 import SMBus

# PCF8574 pin mapping used by nearly all of these backpacks:
#   P0=RS  P1=RW  P2=E  P3=Backlight  P4-P7=D4-D7 (4-bit mode)
LCD_BACKLIGHT = 0x08
LCD_NO_BACKLIGHT = 0x00

ENABLE = 0b00000100
RS_COMMAND = 0x00
RS_DATA = 0x01

LCD_LINE_ADDR = (0x80, 0xC0)  # line 1, line 2 (standard HD44780 DDRAM offsets)
LCD_WIDTH = 16


class LCD1602:
    """One 16x2 character LCD behind a PCF8574 I2C backpack."""

    def __init__(self, bus, address, width=LCD_WIDTH, backlight=True):
        self.bus = bus
        self.address = address
        self.width = width
        self.backlight_flag = LCD_BACKLIGHT if backlight else LCD_NO_BACKLIGHT
        self._init_display()

    # -- low-level I2C/HD44780 plumbing ------------------------------------
    def _write_byte(self, data):
        self.bus.write_byte(self.address, data | self.backlight_flag)

    def _toggle_enable(self, data):
        time.sleep(0.0005)
        self._write_byte(data | ENABLE)
        time.sleep(0.0005)
        self._write_byte(data & ~ENABLE)
        time.sleep(0.0005)

    def _send_nibble(self, nibble, rs_flag):
        data = (nibble & 0xF0) | rs_flag
        self._write_byte(data)
        self._toggle_enable(data)

    def _send_byte(self, byte_val, rs_flag):
        self._send_nibble(byte_val & 0xF0, rs_flag)
        self._send_nibble((byte_val << 4) & 0xF0, rs_flag)

    def _command(self, cmd):
        self._send_byte(cmd, RS_COMMAND)

    def _char(self, ch):
        self._send_byte(ord(ch), RS_DATA)

    def _init_display(self):
        # Standard HD44780 4-bit-mode init sequence.
        self._command(0x33)
        self._command(0x32)
        self._command(0x28)  # 4-bit, 2-line, 5x8 font
        self._command(0x0C)  # display on, cursor off, blink off
        self._command(0x06)  # entry mode: increment, no shift
        self.clear()

    # -- public API ---------------------------------------------------------
    def clear(self):
        self._command(0x01)
        time.sleep(0.002)

    def set_backlight(self, on):
        self.backlight_flag = LCD_BACKLIGHT if on else LCD_NO_BACKLIGHT
        self._write_byte(0x00)

    def write_line(self, text, line=0):
        """Write `text` to line 0 or 1, space-padded/truncated to `width`."""
        if line not in (0, 1):
            raise ValueError("line must be 0 or 1")
        text = text[: self.width].ljust(self.width)
        self._command(LCD_LINE_ADDR[line])
        for ch in text:
            self._char(ch)

    def write_lines(self, line1, line2=""):
        self.write_line(line1, 0)
        self.write_line(line2, 1)


def open_lcd(bus_num, address, **kwargs):
    """Convenience constructor: opens the SMBus and returns an LCD1602."""
    bus = SMBus(bus_num)
    return LCD1602(bus, address, **kwargs)


class _ScrollLine:
    """One line of text that scrolls in place if it's wider than the LCD.

    Non-blocking: call `.step()` once per display-refresh tick (e.g. every
    0.4s from the caller's own loop) and `.render(width)` to get the
    current 16-char window. Lines that fit are simply left-padded/static.
    """

    GAP = "   "  # blank gap between repeats of a scrolling message

    def __init__(self, text, width=LCD_WIDTH):
        self.width = width
        self.set_text(text)

    def set_text(self, text):
        self.text = text or ""
        self.scrolls = len(self.text) > self.width
        self._loop_text = self.text + (self.GAP if self.scrolls else "")
        self._offset = 0

    def step(self):
        if self.scrolls:
            self._offset = (self._offset + 1) % len(self._loop_text)

    def render(self):
        if not self.scrolls:
            return self.text[: self.width].ljust(self.width)
        doubled = self._loop_text + self._loop_text
        return doubled[self._offset: self._offset + self.width]


class LCDStatusDisplay:
    """Wraps an LCD1602 with two independently-scrolling text lines.

    Usage:
        disp = LCDStatusDisplay(lcd)
        disp.set_message("Pico 2W-1 is connected.", "Current power draw: 0.27")
        ...
        disp.tick()   # call on every refresh cycle (e.g. every 0.4s)
    """

    def __init__(self, lcd):
        self.lcd = lcd
        self.line1 = _ScrollLine("")
        self.line2 = _ScrollLine("")
        self._last_rendered = (None, None)

    def set_message(self, line1_text, line2_text=""):
        self.line1.set_text(line1_text)
        self.line2.set_text(line2_text)
        self._last_rendered = (None, None)  # force a redraw

    def tick(self):
        self.line1.step()
        self.line2.step()
        rendered = (self.line1.render(), self.line2.render())
        if rendered != self._last_rendered:
            self.lcd.clear()  # explicit clear before every actual write, so no
            self.lcd.write_lines(*rendered)  # stale characters can linger from
            self._last_rendered = rendered   # a previous, differently-sized line
