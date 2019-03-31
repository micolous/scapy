*****************************
PPP (Point to Point Protocol)
*****************************

Point to Point Protocol is a family of `data link layer`__ protocols.
Traditionally, the protocol is used for passing packets over a serial link,
using a variant of :abbr:`HDLC (High-Level Data Link Control)`.

__ https://en.wikipedia.org/wiki/Data_link_layer

However, there are derivatives of this protocol for encapsulating PPP frames
over :abbr:`ATM (Asynchronous Transfer Mode)` (:abbr:`PPPoA (PPP over ATM)`)
and Ethernet (:abbr:`PPPoE (PPP over Ethernet)`), which are both packet-based
links.  These are commonly used on :abbr:`DSL (Digital Subscriber Line)`
broadband internet connections.

Scapy supports working with PPP in PPPoE and HDLC/Serial links.

.. seealso::

    `Wikipedia: Point-to-Point Protocol <https://en.wikipedia.org/wiki/Point-to-Point_Protocol>`_
        Gives a high level-overview of the PPP protocol family.

    :rfc:`1661`
        The original specification of the Point-to-Point Protocol. Numerous
        other RFCs extend it.

    :doc:`SLIP (Serial Line IP) <slip>`
        A much simpler data link layer protocol for passing packets over a
        serial link.

    :ref:`Packetizers in Scapy <packetizers>`
        Explains how the :py:class:`Packetizer` interface works in Scapy.

HDLC/Serial
===========

``PPPPacketizer`` implements the HDLC-like framing used by PPP over a serial
link.  It also implements the :abbr:`FCS (Frame Check Sequence)` used in the
protocol, in CRC form.

.. seealso::

    :rfc:`1662`
        Describes the HDLC-like framing used for PPP-encapsulated packets
        (implemented by :mod:`PPPPacketizer`).

Creating a PPP connection
-------------------------

