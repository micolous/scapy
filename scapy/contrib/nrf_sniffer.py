# -*- mode: python3; indent-tabs-mode: nil; tab-width: 4 -*-
# nrf_sniffer.py - protocol dissector for nRF sniffer
#
# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Michael Farrell <micolous+git@gmail.com>
# This program is published under a GPLv2 (or later) license
#
# Firmware and documentation related to this module is available at:
# https://www.nordicsemi.com/Software-and-Tools/Development-Tools/nRF-Sniffer
# https://github.com/adafruit/Adafruit_BLESniffer_Python
# https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-nordic_ble.c
#
# scapy.contrib.description = nRF sniffer
# scapy.contrib.status = works

# py2 compat
from __future__ import absolute_import

from scapy.compat import raw
from scapy.config import conf
from scapy.error import warning
from scapy.packet import Packet, bind_layers
from scapy.layers.bluetooth4LE import BTLE, BTLE_RF, BTLE_PPI
from scapy.layers.slip import SLIPPacketizer
from scapy.fields import LEIntField, BitEnumField, BitField, LEShortField, \
    ByteEnumField, ByteField, LenField

try:
    import serial
except ImportError:
    serial = None

NRFS_READ_SIZE = 64
DLT_NORDIC_BLE = 272

PACKET_COMMON_FIELDS = [
    ByteField("version", 2),
    LEShortField("counter", None),
    ByteEnumField("type", None, {
        0x00: "req_follow",
        0x01: "event_follow",
        0x02: "event_device",             # missing from spreadsheet
        0x03: "req_single_packet",        # missing from spreadsheet
        0x04: "resp_single_packet",       # missing from spreadsheet
        0x05: "event_connect",
        0x06: "event_packet",
        0x07: "req_scan_cont",
        0x09: "event_disconnect",
        0x0a: "event_error",              # missing from spreadsheet
        0x0b: "event_empty_data_packet",  # missing from spreadsheet
        0x0c: "set_temporary_key",
        0x0d: "ping_req",
        0x0e: "ping_resp",
        0x0f: "test_command_id",          # missing from spreadsheet
        0x10: "test_result_id",           # missing from spreadsheet
        0x11: "uart_test_start",          # missing from spreadsheet
        0x12: "uart_dummy_packet",        # missing from spreadsheet
        0x13: "switch_baud_rate_req",     # not implemented in FW
        0x14: "switch_baud_rate_resp",    # not implemented in FW
        0x15: "uart_out_start",           # missing from spreadsheet
        0x16: "uart_out_stop",            # missing from spreadsheet
        0x17: "set_adv_channel_hop_seq",
        0xfe: "go_idle",                  # not implemented in FW
    }),
]


class NegativeByteField(ByteField):
    """Field for storing an always-negative unsigned byte."""
    def i2m(self, pkt, x):
        return super(ByteField, self).i2m(pkt, -x)

    def m2i(self, pkt, x):
        return -super(ByteField, self).m2i(pkt, x)


class NRFS2_Packet(Packet):
    name = "nRF Sniffer v2 Packet (device variant)"
    fields_desc = [
        LenField("len", None, fmt="<H", adjust=lambda x: x + 6),
    ] + PACKET_COMMON_FIELDS

    def answer(self, other):
        if isinstance(other, NRFS2_PCAP) and other.payload:
            other = other.payload

        if not isinstance(other, NRFS2_Packet):
            return False

        return ((self.type == 0x01 and other.type == 0x00) or
                (self.type == 0x0e and other.type == 0x0d) or
                (self.type == 0x14 and other.type == 0x13))


class NRFS2_Ping_Request(Packet):
    name = "Ping request"


class NRFS2_Ping_Response(Packet):
    name = "Ping response"
    fields_desc = [LEShortField("version", None), ]


class NRFS2_Packet_Event(Packet):
    name = "Packet event (device variant)"
    fields_desc = [
        ByteField("header_len", 10),

        # Flags (1 byte)
        BitField("reserved", 0, 1),
        BitEnumField("phy", None, 3, {0: 'le-1m', 1: 'le-2m', 2: 'le-coded'}),
        BitField("mic", None, 1),
        BitField("encrypted", None, 1),
        BitField("direction", None, 1),
        BitField("crc_ok", 1, 1),

        ByteField("rf_channel", 0),
        NegativeByteField("rssi", -256),
        LEShortField("event_counter", 0),
        LEIntField("delta_time", 0),       # microseconds
    ]

    def post_build(self, p, pay):
        # Insert the "padding" 6 bytes into the payload.
        o = bytearray()
        o.extend(p[:10])
        o.extend(pay[:6])
        o.append(0)
        o.extend(pay[6:])
        return bytes(o)

    def post_dissect(self, s):
        # Remove the padding from 6 bytes into the payload.
        o = bytearray()
        o.extend(s[:6])
        o.extend(s[7:])
        return bytes(o)

    def convert_to(self, other_cls, **kwargs):
        if other_cls is BTLE_RF:
            # Convert to DLT_BLUETOOTH_LE_LL_WITH_PHDR
            # Retains the payload.
            flags = ['crc_checked', 'sig_power_valid']
            if self.crc_ok:
                flags.append('crc_valid')
            if self.encrypted:
                flags.append('mic_checked')
                if self.mic:
                    flags.append('mic_valid')

            new_pkt = BTLE_RF(
                rf_channel=self.rf_channel,
                signal=self.rssi,
                flags=flags)
            new_pkt /= self.payload.copy()

            return new_pkt

        if other_cls is BTLE_PPI:
            # Convert to BTLE_PPI
            # DISCARDS the payload.
            return BTLE_PPI(
                btle_channel=2402 + (2 * self.rf_channel),  # MHz
                btle_clk_100ns=self.delta_time * 10,
                rssi_max=self.rssi,
                rssi_min=self.rssi,
                rssi_avg=self.rssi
            )

        return Packet.convert_to(self, other_cls, **kwargs)

    @classmethod
    def convert_packet(cls, pkt, **kwargs):
        if isinstance(pkt, BTLE_RF):
            flags = list(pkt.flags)
            new_pkt = cls(
                mic=('mic_checked' in flags and 'mic_valid' in flags),
                encrypted=('mic_checked' in flags),
                crc_ok=('crc_checked' in flags and 'crc_valid' in flags),
                rf_channel=pkt.rf_channel,
                rssi=(pkt.signal if 'sig_power_valid' in flags else -255),
            )
            new_pkt /= pkt.payload.copy()
            return new_pkt

        if isinstance(pkt, BTLE_PPI):
            new_pkt = cls(
                crc_ok=1,  # fake!
                delta_time=pkt.btle_clk_100ns // 10,
                rf_channel=(pkt.btle_channel - 2402) // 2,
                rssi=pkt.rssi_avg,
            )
            return new_pkt

        return Packet.convert_packet(pkt, **kwargs)


class NRFS2_PCAP(Packet):
    """
    PCAP headers for DLT_NORDIC_BLE.

    Nordic's capture scripts either stick the COM port number (yep!) or a
    random number at the start of every packet.

    https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-nordic_ble.c

    The only "rule" is that we can't start packets with ``BE EF``, otherwise
    it becomes a "0.9.7" packet. So we just set "0" here.

    The padding in NRFS2_Packet_Event gets removed.
    """
    name = "nRF Sniffer PCAP header"
    fields_desc = [
        ByteField("board_id", 0),
    ]

    def answer(self, other):
        return self.payload and self.payload.answer(other)

    def convert_to(self, other_cls, **kwargs):
        if other_cls is NRFS2_Packet:
            if NRFS2_PCAP_Packet_Event not in self:
                return NRFS2_Packet() / self

            d = bytearray(raw(self[NRFS2_PCAP_Packet_Event]))

            new_pkt = NRFS2_Packet_Event(d)
            new_pkt = NRFS2_Packet() / new_pkt
            new_pkt.version = self[NRFS2_PCAP_Packet].version
            new_pkt.counter = self[NRFS2_PCAP_Packet].counter
            return new_pkt

        return Packet.convert_to(self, other_cls, **kwargs)

    @classmethod
    def convert_packet(cls, pkt, **kwargs):
        if isinstance(pkt, NRFS2_Packet):
            if NRFS2_Packet_Event not in pkt:
                return cls() / pkt

            # Find and delete the padding byte
            d = bytearray(raw(pkt[NRFS2_Packet_Event]))
            # if len(d) < 16:
            #    assert False, "len={}, d={}".format(len(d), bytes_hex(d))
            # del d[16]

            new_pkt = NRFS2_PCAP_Packet_Event(d)
            new_pkt = NRFS2_PCAP_Packet() / new_pkt
            new_pkt.version = pkt[NRFS2_Packet].version
            new_pkt.counter = pkt[NRFS2_Packet].counter
            return cls() / new_pkt

        if isinstance(pkt, BTLE):
            # Synthetic event type.
            return (cls() /
                    NRFS2_PCAP_Packet() /
                    NRFS2_PCAP_Packet_Event() /
                    BTLE())

        return Packet.convert_packet(pkt, **kwargs)


class NRFS2_PCAP_Packet(NRFS2_Packet):
    name = "nRF Sniffer v2 Packet (pcap variant)"
    fields_desc = [
        LenField("len", None, fmt="<H", adjust=lambda x: x),
    ] + PACKET_COMMON_FIELDS


class NRFS2_PCAP_Packet_Event(NRFS2_Packet_Event):
    name = "Packet event (pcap variant)"

    # Doesn't include any padding.
    def post_build(self, p, pay):
        return p + pay

    def post_dissect(self, s):
        return s


class NRFS_Packetizer(SLIPPacketizer):
    """
    Implements the variant of SLIP used by nRF Sniffer.
    """
    def __init__(self):
        super(NRFS_Packetizer, self).__init__(
            esc=b'\xcd',
            esc_esc=b'\xce',
            end=b'\xbc',
            end_esc=b'\xbd',
            start=b'\xab',
            start_esc=b'\xac',
        )


def nrfs_connect(port, baudrate=460800, timeout=0):
    if serial is None:
        warning("pyserial is required to connect to nRF Sniffer!")
        return

    fd = serial.Serial(port=port, baudrate=baudrate, timeout=timeout)
    return NRFS_Packetizer().make_socket(fd, NRFS2_Packet, NRFS_READ_SIZE)


# Register ourselves for pcap
conf.l2types.register(DLT_NORDIC_BLE, NRFS2_PCAP)

# Wire up differing layers
bind_layers(NRFS2_PCAP, NRFS2_PCAP_Packet)
bind_layers(NRFS2_PCAP_Packet, NRFS2_PCAP_Packet_Event, type=0x06)
bind_layers(NRFS2_Packet, NRFS2_Packet_Event, type=0x06)

# Wire common layers
for c in (NRFS2_PCAP_Packet, NRFS2_Packet):
    bind_layers(c, NRFS2_Ping_Request, type=0x0d)
    bind_layers(c, NRFS2_Ping_Response, type=0x0e)

bind_layers(NRFS2_Packet_Event, BTLE)
