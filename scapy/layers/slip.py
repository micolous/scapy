# -*- mode: python3; indent-tabs-mode: nil; tab-width: 4 -*-
# slip.py - Serial Line IP (RFC 1055)
#
# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Michael Farrell <micolous+git@gmail.com>
# This program is published under a GPLv2 (or later) license
"""
scapy.layers.slip - Serial Line IP (RFC 1055).

Full documentation in docs/scapy/layers/slip.rst.
"""


from __future__ import absolute_import

import os

from scapy.compat import raw
from scapy.error import warning
from scapy.layers.inet import IP
from scapy.packetizer import Packetizer
from scapy.utils import fd_to_file

try:
    import serial
except ImportError:
    serial = None


class SLIPPacketizer(Packetizer):
    """
    Implements RFC 1055 Serial Line IP.

    Full documentation in docs/scapy/layers/slip.rst.
    """
    def __init__(self, esc=b"\333", esc_esc=b"\335", end=b"\300",
                 end_esc=b"\334", start=None, start_esc=None):
        super(SLIPPacketizer, self).__init__()
        if (not esc) or (not esc_esc):
            raise ValueError("Both esc and esc_esc must be always declared")

        if (not end) or (not end_esc):
            raise ValueError("Both end and end_esc must be always declared")

        if bool(start) != bool(start_esc):
            raise ValueError("start, start_esc must both be declared, or "
                             "neither declared")

        self.esc = raw(esc)
        self.esc_esc = raw(esc_esc)

        self.start = raw(start) if start else None
        self.start_esc = raw(start_esc) if start_esc else None

        self.end = raw(end)
        self.end_esc = raw(end_esc)

    def find_end(self):
        p = self.buffer.find(self.end)
        if p > -1:
            p += len(self.end)
        return p

    def decode_frame(self, length):
        # Internal-only method. This is called by data_received to fetch a
        # single bucket.
        o = bytearray()
        i = 0

        # Discard end-of-packet marker
        length -= len(self.end)

        if self.start:
            start_idx = self.buffer.find(self.start, i, length)
            if start_idx == -1:
                # No start flag, or start is after the end.
                # Discard this message.
                return

            while start_idx > -1:
                i = start_idx + len(self.start)
                start_idx = self.buffer.find(self.start, i, length)

        # start decoding packets
        # stop when we reach an "end" sequence
        while i < length:
            # find an escape sequence
            esc_pos = self.buffer.find(self.esc, i, length)

            if esc_pos == -1:
                # There was no escape sequence, copy the rest of the message.
                o.extend(self.buffer[i:length])
                i = length
            else:
                # There was an escape sequence. Handle it.
                if i < esc_pos:
                    # Add everything before the sequence to the buffer
                    o.extend(self.buffer[i:esc_pos])

                i = esc_pos + len(self.esc)
                if i >= length:
                    # EOF at position!
                    break

                i, r = self.handle_escape(i, length)
                if r is None:
                    # buffer overrun
                    break

                o.extend(r)

        return bytes(o)

    def handle_escape(self, i, end_msg_pos):
        """Called after an escape sequence was read."""
        if self.buffer.startswith(self.esc_esc, i):
            i += len(self.esc_esc)
            o = self.esc
        elif self.buffer.startswith(self.end_esc, i):
            i += len(self.end_esc)
            o = self.end
        elif self.start_esc and self.buffer.startswith(self.start_esc, i):
            i += len(self.start_esc)
            o = self.start
        else:
            # Unknown sequence (protocol violation).
            # "leave the byte alone" per RFC
            o = b''

        if i >= end_msg_pos:
            # buffer overrun
            return i, None

        return i, o

    def encode_frame(self, pkt):
        """Encodes a packet in binary form with SLIP."""
        d = super(SLIPPacketizer, self).encode_frame(pkt)
        o = bytearray()
        if self.start:
            o.extend(self.start)

        i = 0
        while i < len(d):
            # find an escape sequence
            esc_pos = d.find(self.esc, i)
            end_pos = d.find(self.end, i)
            start_pos = d.find(self.start, i) if self.start else -1

            apos = list(filter(lambda x: x > -1,
                               (esc_pos, end_pos, start_pos)))

            if not apos:
                # There are no more escape characters to escape.
                o.extend(d[i:])
                break

            fpos = min(apos)
            if fpos > i:
                # copy bytes up to the first section to escape
                o.extend(d[i:fpos])

            o.extend(self.esc)
            if esc_pos == fpos:
                # escape the escape
                o.extend(self.esc_esc)
                i = fpos + len(self.esc)
            elif end_pos == fpos:
                # escape the end
                o.extend(self.end_esc)
                i = fpos + len(self.end)
            elif start_pos == fpos:
                # escape the end
                o.extend(self.start_esc)
                i = fpos + len(self.start)

        o.extend(self.end)
        return bytes(o)


def slip_socket(fd, packet_class=None, default_read_size=None):
    """SLIP socket around a given file-like object."""
    fd = fd_to_file(fd)
    return SLIPPacketizer().make_socket(fd, packet_class, default_read_size)


def slip_ipv4_socket(fd, default_read_size=None):
    """SLIP socket around a given file-like object for IPv4 payloads."""
    fd = fd_to_file(fd)
    return slip_socket(fd, IP, default_read_size)


def slip_serial(port, baudrate=9600, timeout=0, packet_class=IP,
                default_read_size=None):
    """
    Creates a SLIP connection on a given serial port.

    This method requires PySerial.

    :param port: Path to the port to use, eg: ``/dev/ttyS0``
    :param baudrate: Baud rate to connect at.
    :param timeout: Set to 0, so that select-based polling works.
    :param packet_class: Packet class to use on the link. Defaults to IP.
    :return: A SuperSocket which is connected to the serial port.
    """
    if serial is None:
        warning("pyserial is required to use a real serial port!")
        return

    fd = serial.Serial(port=port, baudrate=baudrate, timeout=timeout)
    return slip_socket(fd, packet_class, default_read_size)


def slip_pty(packet_class=IP, default_read_size=None):
    """
    Makes a slip virtual PTY.

    Note: Consider using TunTapInterface rather than this method.
    """

    parent_fd, child_fd = os.openpty()
    child_fn = os.ttyname(child_fd)
    parent_socket = slip_socket(parent_fd, packet_class, default_read_size)

    return parent_socket, child_fn, child_fd
