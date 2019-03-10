***********
nRF Sniffer
***********

This module implements communication with `nRF Sniffer`__, a firmware for Nordic
Semiconductor's nRF51 / nRF52 family of Bluetooth Low Energy SoCs.

__ https://www.nordicsemi.com/Software-and-Tools/Development-Tools/nRF-Sniffer

To use this module, you will need:

  * a compatible Nordic nRF51 / nRF52 module
  * a TTL UART cable which is connected to the nRF module
  * pyserial

Note: The nRF has a TTL-level UART. Connecting it to RS-232 PC serial ports will
not work, and damage the nRF.

If you don't already have `nRF Sniffer v2`__ installed on your module, you'll
also need:

__ https://www.nordicsemi.com/Software-and-Tools/Development-Tools/nRF-Sniffer

  * compiled binaries for nRF Sniffer v2
  * a flash programmer, such as an ST-Link v2
  * OpenOCD later than 0.10.0

OpenOCD 0.10.0 doesn't include all the components needed for flashing nRF52
chips, and some of the commands have changed from 0.10.0. If there's a newer
version, run that, otherwise run the version on git master.

Note: This module **does not** use Nordic's Python scripts for communicating
with the sniffer.  However, it *can* produce output in a compatible format.

Note: This module only supports the nRF Sniffer v2 protocol and pcap formats.

Getting the sniffer running
===========================

Identify the correct binary
---------------------------

The binaries needed for modules depend on the chip that you're using:

TODO

Wiring for flashing
-------------------

For flashing, you'll need to wire up these pins.  This presumes you're using an
ST-Link v2 programming dongle:

  * ``VDD`` -> ``3.3v``
  * ``GND`` -> ``GND``
  * ``SWDCLK`` -> ``SWCLK``
  * ``SWDIO`` -> ``SWDIO``
  * ``RESET (P0.21)`` -> ``RESET``

TODO note openocd commands here

Wiring for the serial connection
--------------------------------

Now that you've flashed the nRF, you can connect a serial UART.

The following connections must be made between the nRF module and your TTL UART
cable:

  * ``VDD`` -> +3v supply
  * ``GND`` -> ground
  * ``RTS (P0.05)`` -> ``CTS`` on UART
  * ``TXD (P0.06)`` -> ``RXD`` on UART
  * ``CTS (P0.07)`` -> ``RTS`` on UART
  * ``RXD (P0.08)`` -> ``TXD`` on UART

The nRF52 development kit already has these pins hooked up correctly, and
has an on-board USB TTL UART. Other boards are a bit more involved.

If you don't have an ``RTS`` on your UART cable, you must connect
``CTS (P0.07)`` to ``GND``. Failure to do so will cause ``CTS`` to float -- and
the nRF Sniffer firmware will stop sending data after a few bytes.

Using the sniffer
=================

When the sniffer powers on, it will immediately start sending all broadcast
frames that it can detect, and automatically channel-hop.

.. code-block:: python3

    load_contrib('nrf_sniffer')

    # On Linux, you'll use something like:
    sniffer = nrfs_connect('/dev/ttyUSB0')

    # On OSX, you'll use something like:
    sniffer = nrfs_connect('/dev/tty.usbserial-xxxxx')

You can then start capturing packets:

.. code-block:: pycon

    >>> pkts = s.sniff(timeout=10)
    >>> pkts
    <Sniffed: TCP:0 UDP:0 ICMP:0 Other:1788>

This will give you a ``PacketList`` of ``NRFS2_Packet``:

TODO

These packets can be saved to disk, but Nordic's Python scripts subtly change
the packet format, so ``DLT_NORDIC_BLE`` (272) is read as ``NRFS2_PCAP`` in
Scapy. Unfortunately, it is this modified format that tools like Wireshark
support.

However, the packets are easily converted to ``DLT_NORDIC_BLE`` or
``DLT_BLUETOOTH_LE_LL`` format:

.. code-block:: python3

    # Convert to DLT_NORDIC_BLE (272) format:
    nordic_pcap_pkts = pkts.convert_to(NRFS2_PCAP)

    # Convert to DLT_BLUETOOTH_LE_LL (251) format:
    ble_pcap_pkts = pkts.convert_to(BTLE)

    # Either of these can be written to pcap files without issue:
    wrpcap('/tmp/ble-nordic.pcap', nordic_pcap_pkts)
    wrpcap('/tmp/ble-ll.pcap', ble_pcap_pkts)

As for why you'd use each one:

  * ``DLT_NORDIC_BLE`` includes all the packet metadata from the sniffer,
    including the channel, signal strength, whether the checksums matched, and
    additional timing information. This is not as well supported, and there are
    at least three versions of the format.

  * ``DLT_BLUETOOTH_LE_LL`` contains just the Bluetooth LE link-layer, resulting
    in smaller files. It is an older and better defined format, that is
    supported by more tools.

You could also store the ``NRFS2_Packet`` lists directly, but these do not have
a registered libpcap protocol ID.

TODO note wireshark versions
