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

If you don't already have `nRF Sniffer v2`__ installed on your module, you'll
also need:

__ https://www.nordicsemi.com/Software-and-Tools/Development-Tools/nRF-Sniffer

  * compiled binaries for nRF Sniffer v2 :ref:`appropriate for your SoC
  <nrfs-binary>`

  * :ref:`a method to flash the binary <nrfs-flash-methods>`

Note: This module **does not** use Nordic's Python scripts for communicating
with the sniffer.  However, it *can* produce output in a compatible format.

Note: This module only supports the nRF Sniffer v2 protocol and pcap formats. If
you have nRF Sniffer v0 or v1, you'll need to upgrade it first.

.. _nrfs-binary:

Identify the correct binary
---------------------------

The nRF Sniffer ZIP contains binaries in the ``hex/`` directory, as
``sniffer_pcaXXXXX_YYYYYYY.hex``:

 * ``pcaXXXXX`` is a target development board
 * ``YYYYYYY`` references a specific version of nRF sniffer (likely a ``git``
   commit in an internal Nordic repository.)

The binaries needed for modules depend on the chip that you're using:

========  ========  ===============================
Board ID  nRF SoC   Description
========  ========  ===============================
PCA10000  nRF51822  Development board (obsolete)
PCA10001  nRF51822  Development board (obsolete)
PCA10028  nRF51422  Development board
PCA10031  nRF51822  Development kit dongle
PCA10040  nRF52810  Development board
PCA10056  nRF52840  Development board
PCA10068  ???       ???
========  ========  ===============================

While these all target particular development boards, as long as you can wire a
serial connection in the same way as on the development board, you can use
alternative modules.

.. _nrfs-flash-methods:

Methods to flash the binary
---------------------------

Most of Nordic's development boards come with an on-board J-Link programmer.
This can be flashed with anything that supports J-Link devices.

Some boards come with a serial (or USB) bootloader.  This can be flashed through
board-specific tools.

If all else fails, you can use an external flash programmer (like ST-Link v2)
with OpenOCD **later** than v0.10.0.

OpenOCD 0.10.0 doesn't include all the components needed for flashing nRF52
chips, and some of the commands have changed from 0.10.0. If there's a newer
version, run that, otherwise run the version on git master.


Flashing nRF Sniffer
====================

.. note::

    This only describes how to use an external programmer.

.. note::

    nRF Sniffer already comes with an appropriate `Softdevice`__.

Flashing with an external programmer
------------------------------------

Wiring the board
^^^^^^^^^^^^^^^^

This presumes you're using an ST-Link v2 programming dongle on an nRF52810:

 * ``VDD`` -> ``3.3v``
 * ``GND`` -> ``GND``
 * ``SWDCLK`` -> ``SWCLK``
 * ``SWDIO`` -> ``SWDIO``
 * ``RESET (P0.21)`` -> ``RESET``

If you have a different board, you'll need to connect the correct ``RESET``
line.  Some boards may not label the other pins in an obvious way -- consult its
datasheet for more information.

Other programmers generally have the same sorts of pins available.

Flashing the sniffer
^^^^^^^^^^^^^^^^^^^^

You can verify the nRF board is detected by the programmer
(non-destructively) with:

.. code-block:: console

    $ openocd -f interface/stlink.cfg -f target/nrf52.cfg \
        -c init -c "reset init" -c halt -c reset -c exit
    Open On-Chip Debugger 0.10.0+dev-00696-g6f66267f (2019-02-25-00:36)
    [...]
    Info : STLINK V2J17S4 (API v2) VID:PID 0483:3748
    Info : Target voltage: 3.240945
    Info : nrf52.cpu: hardware has 6 breakpoints, 4 watchpoints
    Info : Listening on port 3333 for gdb connections
    target halted due to debug-request, current mode: Thread
    xPSR: 0x01000000 pc: 0xfffffffe msp: 0xfffffffc

If you get an error like ``init mode failed (unable to connect to the target)``,
then check your connections before trying again.

Then, once you're ready, you can flash the board with:

.. code-block:: console

    $ openocd -f interface/stlink.cfg -f target/nrf52.cfg \
        -c init -c "reset init" -c halt -c "nrf5 mass_erase" \
        -c "program ./sniffer_pcaXXXXX_YYYYYYY.hex verify" \
        -c reset -c exit
    Open On-Chip Debugger 0.10.0+dev-00696-g6f66267f (2019-02-25-00:36)
    [...]
    Info : clock speed 1000 kHz
    Info : STLINK V2J17S4 (API v2) VID:PID 0483:3748
    Info : Target voltage: 3.240945
    Info : nrf52.cpu: hardware has 6 breakpoints, 4 watchpoints
    Info : Listening on port 3333 for gdb connections
    target halted due to debug-request, current mode: Thread
    xPSR: 0x01000000 pc: 0xfffffffe msp: 0xfffffffc
    Info : nRF52832-QFAA(build code: B0) 512kB Flash
    target halted due to debug-request, current mode: Thread
    xPSR: 0x01000000 pc: 0xfffffffe msp: 0xfffffffc
    ** Programming Started **
    auto erase enabled
    Warn : using fast async flash loader. This is currently supported
    Warn : only with ST-Link and CMSIS-DAP. If you have issues, add
    Warn : "set WORKAREASIZE 0" before sourcing nrf51.cfg/nrf52.cfg to disable it
    wrote 12288 bytes from file ./sniffer_pca10040_1c2a221.hex in 1.078249s (11.129 KiB/s)
    ** Programming Finished **
    ** Verify Started **
    verified 11012 bytes in 0.065595s (163.944 KiB/s)
    ** Verified OK **

Wiring a TTL UART (serial connection)
=====================================

.. note::

    Boards with a USB port (such as the nRF development kits) already have
    these pins hooked up correctly, and has an on-board USB TTL UART.

    This section can be skipped for such boards.

The following connections must be made between the nRF module and your TTL UART
cable:

 * ``VDD`` -> +3.3v supply
 * ``GND`` -> ground
 * ``RTS (P0.05)`` -> ``CTS`` on UART
 * ``TXD (P0.06)`` -> ``RXD`` on UART
 * ``CTS (P0.07)`` -> ``RTS`` on UART
 * ``RXD (P0.08)`` -> ``TXD`` on UART

If you don't have an ``RTS`` connector on your TTL UART cable, you **must+**
connect the nRF's ``CTS (P0.07)`` to ``GND``. Failure to do so will cause
``CTS`` to float -- and the nRF Sniffer firmware will stop sending data after a
few bytes.

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
    additional timing information.

    This is not as well supported, and there are at least three versions of
    the format (this module only supports version 2).

  * ``DLT_BLUETOOTH_LE_LL`` contains just the Bluetooth LE link-layer, resulting
    in smaller files.

    It is an older and better defined format, that is supported by more tools.

You could also store the ``NRFS2_Packet`` lists directly, but these do not have
a registered libpcap protocol ID.

TODO note wireshark versions
