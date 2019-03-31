# -*- mode: python3; indent-tabs-mode: nil; tab-width: 4 -*-
# packetizer.py - Tools for implementing a data-link layer on a stream.
#
# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Michael Farrell <micolous+git@gmail.com>
# This program is published under a GPLv2 (or later) license
"""
scapy.packetizer - Tools for implementing a data-link layer on a stream.

Full documentation in docs/scapy/advanced_usage.rst.
"""

from __future__ import absolute_import

import abc
from threading import Lock
import time
from scapy.modules.six import binary_type
from scapy.modules.six.moves.queue import Queue, Empty

from scapy.compat import ABC, raw
from scapy.config import conf
from scapy.supersocket import SimpleSocket, SuperSocket


class Packetizer(ABC):
    """
    Packetizer defines an interface for the implementation of data-link layers.

    It contains some buffering semantics for handling incomplete data.

    Full documentation in docs/scapy/advanced_usage.rst.
    """
    def __init__(self):
        self.buffer = bytearray()
        self._buffer_lock = Lock()

    def clear_buffer(self):
        """Clears the buffer."""
        with self._buffer_lock:
            self.buffer = bytearray()

    def data_received(self, data):
        """Adds data to the decoding buffer, and starts processing it."""
        with self._buffer_lock:
            self.buffer.extend(data)

            frame_length = self.find_end()
            while frame_length > -1:
                p = self.decode_frame(frame_length)
                del self.buffer[:frame_length]

                if p:
                    yield p, time.time()

                frame_length = self.find_end()

    @abc.abstractmethod
    def find_end(self):
        """Find the end of the first packet in the buffer."""
        return -1

    @abc.abstractmethod
    def decode_frame(self, length):
        """Gets the bytes for a single frame in the buffer."""
        pass

    @abc.abstractmethod
    def encode_frame(self, pkt):
        """Encodes frame bytes (or a Packet) for transmission."""
        return raw(pkt)

    def make_socket(self, fd, packet_class=None, default_read_size=None):
        return PacketizerSocket(fd, self, packet_class, default_read_size)


class PacketizerSocket(SimpleSocket):
    """Wrapper for Packetizer that turns a file-like object into a SuperSocket.

    Full documentation in docs/scapy/advanced_usage.rst.
    """
    def __init__(self, fd, packetizer, packet_class=None,
                 default_read_size=None):
        # This allows subclasses to pass "None" to accept our default.
        default_read_size = (default_read_size if default_read_size is not None
                             else 256)

        super(PacketizerSocket, self).__init__(fd, default_read_size)
        if not isinstance(packetizer, Packetizer):
            raise TypeError('packetizer must implement Packetizer interface')

        self.packet_class = packet_class or conf.raw_layer
        self.packetizer = packetizer
        self._packet_queue = Queue()

        self.promisc = True

    def recv_raw(self, x=None):
        if x is None:
            x = self.default_read_size

        try:
            pkt, ts = self._packet_queue.get_nowait()
            return self.packet_class, pkt, ts
        except Empty:
            # Well, looks like we need to do some work...
            pass

        # read some bytes
        for p in self.packetizer.data_received(self.ins.read(x)):
            self._packet_queue.put(p)

        # Do we have some packets now?
        try:
            pkt, ts = self._packet_queue.get_nowait()
            return self.packet_class, pkt, ts
        except Empty:
            return None, None, None

    def send(self, x):
        if not isinstance(x, (self.packet_class, binary_type)):
            x = self.packet_class() / x

        sx = raw(x)
        if hasattr(x, 'sent_time'):
            x.sent_time = time.time()
        self.ins.write(self.packetizer.encode_frame(sx))

    def has_packets(self):
        """Returns True if there are packets already in the queue."""
        return not self._packet_queue.empty()

    @staticmethod
    def select(sockets, remain=conf.recv_poll_rate):
        # Before passing off to base select, see if we have anything ready in
        # a queue
        queued = [s for s in sockets
                  if isinstance(s, PacketizerSocket) and s.has_packets()]
        if queued:
            return queued, None

        return SuperSocket.select(sockets, remain)
