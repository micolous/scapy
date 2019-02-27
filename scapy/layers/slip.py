# -*- mode: python3; indent-tabs-mode: nil; tab-width: 4 -*-
# slip.py - Serial Line IP (RFC 1055)
#
# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Michael Farrell <micolous+git@gmail.com>
# This program is published under a GPLv2 (or later) license

from __future__ import absolute_import
from threading import Lock
import time
from queue import SimpleQueue, Empty

from scapy.config import conf
from scapy.data import MTU
from scapy.modules import six
from scapy.supersocket import SuperSocket


class SLIPPacketizer(object):
    """
    SLIPPacketizer implements RFC 1055 Serial Line "IP".
    
    "IP" is in quotation marks, because nothing about the RFC requires that
    you use it for IPv4.

    Each packet is followed by the ``end`` (bytes). When this is read, the
    ``callback`` parameter of the ``data_recived`` method is called with the
    decoded bytes.

    In order to include literals containing ``start`` or ``end``, one escapes
    them with ``esc``, followed by the ``start_esc`` or ``end_esc``
    respectively.

    In order to include a literal ``esc``, then the sequence is ``esc`` then
    ``esc_esc``.

    In addition to the RFC:
    
    * one can **also** require that ``start`` (bytes) must be at the start of
      each message. This makes it easier for each side to restart a packet
      mid-transmission.
    * this supports multi-byte ``end``, ``esc`` and ``start`` sequences
      (and also for escape sequences).

    By default, this class operates according to RFC 1055.

    Args:
        esc (bytes): The sequence that precedes all escape sequences.
        esc_esc (bytes): The sequence for including a literal ``esc``.
        end (bytes): The sequence that terminates each packet.
        end_esc (bytes): The sequence for including a literal ``end``.
        start (bytes, optional): The sequence that precedes each packet.
        start_esc (bytes, optional): The sequence for including a literal
                                     ``start``.
        discard_empty (bool): By default, any 0-byte packets will be discarded.
                              Some systems may use this as a keep-alive.

    """
    def __init__(self, esc=b"\333", esc_esc=b"\335", end=b"\300", end_esc=b"\334", start=None, start_esc=None, discard_empty=True):
        if (not esc) or (not esc_esc):
            raise RuntimeError("Both esc and esc_esc must be always declared")

        if (not end or not end_esc):
            raise RuntimeError("Both end and end_esc must be always declared")
        
        if bool(start) != bool(start_esc):
            raise RuntimeError("start, start_esc must both be declared, or neither declared")

        self.esc = raw(esc)
        self.esc_esc = raw(esc_esc)

        self.start = raw(start) if start else None
        self.start_esc = raw(start_esc) if start_esc else None

        self.end = raw(end)
        self.end_esc = raw(end_esc)
        
        self.discard_empty = bool(discard_empty)

        self.buffer = bytearray()
        self.buffer_lock = Lock()

    def clear_buffer(self):
        """
        Clears the buffer.

        This will cause any partial packets to be discarded.
        
        If ``start`` is not set and a packet is in progress, a corrupted packet
        will be returned in the next callback.
        
        This method blocks while acquiring the buffer lock.
        """
        with self.buffer_lock:
            self.buffer = bytearray()

    def data_received(self, data, callback):
        """
        Adds data to the decoding buffer, and starts processing it.

        This method will call ``callback`` once for each complete packet that
        was received.

        This method blocks while acquiring the buffer lock.

        Args:
            data (bytes): data to append to the buffer.
            callback (callable): a method that takes one parameter, a tuple of
                                 the decoded packet bytes and a timestamp.
        """
        with self.buffer_lock:
            self.buffer.extend(data)
            
            end_msg_pos = self.buffer.find(self.end)
            while end_msg_pos > -1:
                if self.discard_empty and end_msg_pos == 0:
                    del self.buffer[:len(self.end)]
                else:
                    # split out the decoded packet
                    p = self._decode_packet(end_msg_pos)
                    del self.buffer[:end_msg_pos + len(self.end)]

                    if p:
                        callback((p, time.time()))
            
                end_msg_pos = self.buffer.find(self.end)

    def _decode_packet(self, end_msg_pos):
        # Internal-only method. This is called by data_received to fetch a
        # single bucket.
        o = bytearray()
        i = 0
        if self.start:
            start_idx = self.buffer.find(self.start, i, end_msg_pos)
            if start_idx == -1:
                # No start flag, or start is after the end.
                # Discard this message.
                return

            while start_idx > -1:
                i = start_idx + len(self.start)
                start_idx = self.buffer.find(self.start, i, end_msg_pos)

        # start decoding packets
        # stop when we reach an "end" sequence
        while i < end_msg_pos:
            # find an escape sequence
            esc_pos = self.buffer.find(self.esc, i, end_msg_pos)
            
            if esc_pos == -1:
                # There was no escape sequence, copy the rest of the message.
                o.extend(self.buffer[i:end_msg_pos])
                i = end_msg_pos
            else:
                # There was an escape sequence. Handle it.
                if i < esc_pos:
                    # Add everything before the sequence to the buffer
                    o.extend(self.buffer[i:esc_pos])

                i = esc_pos + len(self.esc)
                if i >= end_msg_pos:
                    # EOF at position!
                    break

                i, r = self.handle_escape(i, end_msg_pos)
                if r is None:
                    # buffer overrun
                    break

                o.extend(r)


        return o

    def handle_escape(self, i, end_msg_pos):
        """
        "Internal" method, called after an escape sequence was read.
        
        
        """
        o = None
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
            i += 1
            o = self.esc

        if i >= end_msg_pos:
            # buffer overrun
            return i, None

        return i, o

    def encode_data(self, pkt):
        """
        Encodes a packet in binary form with SLIP.

        This does NOT use the buffer lock.
        """
        d = raw(pkt)
        o = bytearray()
        if self.start:
            o.extend(self.start)

        i = 0
        while i < len(d):
            # find an escape sequence
            esc_pos = d.find(self.esc, i)
            end_pos = d.find(self.end, i)
            start_pos = d.find(self.start, i) if self.start else -1
            
            apos = list(filter(lambda x: x > -1, (esc_pos, end_pos, start_pos)))

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


class SLIPSocket(SuperSocket):
    """
    SLIPSocket implements a wrapper around a file descriptor to packetise a
    Serial Line IP stream.
    
    By default, this uses ``SLIPPacketizer``, which follows RFC 1055. One may
    specify a different ``packetizer`` implementation for alternate
    end/escape/start markers.
    
    This implementation sends packets to the ``Raw`` layer by default.  One can
    specify a reference to another ``Packet`` subclass with ``cls``.
    
    Note that nothing about RFC 1055 specifies a particular packet type, and
    there is no requirement that it contains IPv4.
    
    Args:
        fd: a file-like object to stream data from. This can be a file on
            disk, or something else that implements the interface (such as
            pyserial)
        packetizer: a class to converts the stream into a series of packets.
                    By default, this uses ``SLIPPacketizer``.
        cls: a ``Packet`` subclass for decoding the packets with. By default,
             this uses the ``Raw`` type.
    """
    def __init__(self, fd, packetizer=None, cls=None):
        self.ins = self.outs = fd
        self.packetizer = packetizer or SLIPPacketizer()
        self.cls = cls or conf.raw_layer
        self.packet_queue = SimpleQueue()

        # This prevents us from erroring in sr() when there's no packet.
        self.promisc = True

    def recv_raw(self, x=MTU):
        try:
            pkt, ts = self.packet_queue.get_nowait()
            return self.cls, pkt, ts
        except Empty:
            # Well, looks like we need to do some work...
            pass

        # read some bytes
        self.packetizer.data_received(self.ins.read(x), self.packet_queue.put)
        
        # Do we have some packets now?
        try:
            pkt, ts = self.packet_queue.get_nowait()
            return self.cls, pkt, ts
        except Empty:
            return

    def send(self, x):
        sx = raw(x)
        if hasattr(x, 'sent_time'):
            x.sent_time = time.time()
        self.ins.write(self.packetizer.encode_data(sx))

    @staticmethod
    def select(sockets, remain=conf.recv_poll_rate):
        # Before passing off to base select, see if we have anything ready in
        # a queue
        queued = [s for s in sockets if not s.packet_queue.empty()]
        if queued:
            return queued, None
        
        return SuperSocket.select(sockets, remain)

