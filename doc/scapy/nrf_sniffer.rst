***********
nRF Sniffer
***********

Implements serial connectivity with nRF Sniffer.

https://www.nordicsemi.com/Software-and-Tools/Development-Tools/nRF-Sniffer

This requires:

  * a compatible Nordic nRF51/52 with nRF Sniffer installed
  * a TTL UART which is connected to the nRF
  * pyserial

The following pins need to be connected for this to work:

  * VDD -> +3v supply
  * GND -> ground
  * RTS (P0.05) -> CTS on UART
  * TXD (P0.06) -> RXD on UART
  * CTS (P0.07) -> RTS on UART (or ground)
  * RXD (P0.08) -> TXD on UART

The nRF52 development kit already has these pins hooked up correctly, and
has an on-board USB UART. Other boards are a bit more involved.

Note: CTS on the nRF board must be connected to either RTS on your UART, or
to ground. Failure to do so will cause the GPIO to float. A symptom is that
you'll get a few bytes from the controller, and then it will stop.

The nRF has a TTL-level UART. Connecting it to PC serial ports will not
work, and damage the nRF.

The "native" type of this socket is ``NRFS2_Packet``. This represents the
actual wire format from nRF Sniffer.

However, Nordic's scripts rewrite this packet, and _that_ format is used
for ``DLT_NORDIC_BLE`` (rather than the actual wire format).  For
compatibility with these tools, by default the flag ``convert_pcap=True``
is set, which converts packets into ``NRFS2_PCAP``.

One could also use the ``DLT_BLUETOOTH_LE_LL`` compatible format with:

.. code-block:: python3

    bpkts = PacketList([x[BTLE] for x in pkts if BTLE in x], "Sniffed")
    wrpcap("/tmp/mycap.pcap", bpkts)

