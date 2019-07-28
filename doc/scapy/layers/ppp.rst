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

PPP Packet Types
================

The base packet types are:

.. py:class:: HDLC([address: int], [control: int])

    The HDLC-like framing described in :rfc:`1662`. Without negotiation between
    the peers, this is the default framing for PPP.

    When :rfc:`1661#section-6.6` Address and Control Field Compression has been
    negotiated between the peers, this layer is removed and :py:class:`PPP` is
    used.

.. py:class:: PPP_([proto: int])

    PPP with :rfc:`1661#section-6.5` Protocol Field Compression.

    When negotiated between peers, and the protocol ID would fit in 1 byte,
    this is used instead of :py:class:`PPP`.

    It can be stacked on :py:class:`HDLC`.

.. py:class:: PPP([proto: int])

    *This is the best packet type to use for Scapy.* It automatically
    dispatches to :py:class:`PPP_` and :py:class:`HDLC` as appropriate with
    :py:meth:`dispatch_hook`.

    It can be stacked on :py:class:`HDLC`.

    .. py:classmethod:: dispatch_hook([_pkt: bytes]) -> Type[Packet]

        Automatically selects the correct packet type for the given packet
        data, between :py:class:`HDLC`, :py:class:`PPP`, and :py:class:`PPP_`.

.. note::

    None of these framing types include the :abbr:`FCS (Frame Check Sequence)`.
    This is implemented by :py:class:`PPPPacketizer`.

Serial
======

:py:class:`PPPPacketizer` implements the HDLC-like framing used by PPP over a
serial link.  It also implements the :abbr:`FCS (Frame Check Sequence)` used in
the protocol, in CRC form.

.. note::

    PPP requires a complex negotiation sequence to establish a connection, and
    Scapy doesn't yet implement it.

    If you want to establish a connection over a serial link with Scapy, use
    :doc:`Serial Line IP <slip>` for now.

    If you want to attach a local, virtual network interface to Scapy, use
    :py:class:`TunTapInterface` instead.

.. seealso::

    :rfc:`1662`
        Describes the HDLC-like framing used for PPP-encapsulated packets
        (implemented by :mod:`PPPPacketizer`).

.. py:class:: PPPPacketizer(fcs_mode=FCS_MODE_CRC16, fcs_check: bool = True)

    PPP octet-stuffed framing (:rfc:`1662#section-4`) implementation.

    This also supports handling :abbr:`FCS (Frame Check Sequence)`, which is
    generally a form of :abbr:`CRC (Cyclic Redundancy Check)`.

    :param fcs_mode: FCS operation mode. Set to one of the ``FCS_MODE_``
        constants. Defaults to :py:data:`FCS_MODE_CRC16`
    :param bool fcs_check: True (default) to drop frames with invalid FCS. If
        set to False, the FCS value is removed but never checked. Errors
        counters are not incremented.

    .. py:data:: FCS_MODE_NONE

        Don't include any FCS.

        If used on packets with FCS, this appears as :py:class:`Padding` at the
        end of the packet.

    .. py:data:: FCS_MODE_CRC16

        FCS is a ``CRC16-X25``.

    .. py:data:: FCS_MODE_CRC32

        FCS is a ``CRC32``.

        .. warning::

            This operation mode is untested.

    .. py:attribute:: fcs_mode

        FCS operation mode, set to one of the ``FCS_MODE_`` constants described
        above.

        May be changed at runtime. Changes do not have any effect on
        complete packets that have already been placed in the
        :py:attr:`~PacketizerSocket._packet_queue`.

    .. py:attribute:: fcs_check

        Whether to check the FCS, and drop frames that are invalid.

        If set to True, the FCS will be checked, invalid frames will be dropped,
        and the :py:attr:`fcs_errors` counter will be incremented.

        If set to False, the FCS will not be checked, invalid frames will be
        permitted, and the :py:attr:`fcs_errors` counter will not be
        incremented.

        May be changed at runtime. Changes do not have any effect on
        complete packets that have already been placed in the
        :py:attr:`~PacketizerSocket._packet_queue`.

    .. py:attribute:: fcs_errors

        Integer counter, which increments on FCS errors.  Only increments when
        :py:attr:`fcs_check` is True.

    .. py:method:: make_socket(fd, [packet_class=None,] \
                               [default_read_size: int]) -> PPPPacketizerSocket

        See :py:meth:`PacketizerSocket.make_socket`.

        :param packet_class: parameter is ignored.
        :rtype: PPPPacketizerSocket

.. py:class:: PPPPacketizerSocket(fd: file, packetizer: Packetizer, \
                             [default_read_size: int])

    Implements :py:class:`PacketizerSocket` for :rfc:`1661` and :rfc:`1662`
    PPP.

    See :py:class:`PacketizerSocket` for non-PPP-specific usage.

    .. note::

        The ``packet_class`` and ``packet_classes`` parameters have been
        removed.

    .. py:attribute:: enable_pfc

        If True, enables :rfc:`1661#section-6.5` Protocol Field Compression on
        sent packets. This allows the transmission of :py:class:`PPP_` packets.

        This defaults to False, and must only be enabled after negotiation with
        the peer.

        This change takes effect on the next call to :py:meth:`send`.

        This does not impact the reception of packets --
        :py:meth:`PPP.dispatch_hook` always auto-detects them, even if it
        wasn't negotiated.

    .. py:attribute:: enable_acfc

        If True, enables :rfc:`1661#section-6.6` Address and Control Field
        Compression on sent packets.  This has the effect of removing the
        :py:class:`HDLC` layer from :py:class:`PPP` or :py:class:`PPP_`
        packets.

        :py:class:`PPP_LCP` payloads are always transmitted with a
        :py:class:`HDLC` layer, regardless of this setting.

        This defaults to False, and must only be enabled after negotiation with
        the peer.

        This change takes effect on the next call to :py:meth:`send`.

        This does not impact the reception of packets --
        :py:meth:`PPP.dispatch_hook` always auto-detects them, even if it
        wasn't negotiated.

    .. py:method:: send(x) -> None

        Extension of :py:meth:`PacketizerSocket.send`:

        If ``x`` is a :py:class:`HDLC`, :py:class:`PPP` or :py:class:`PPP_`,
        this will automatically convert it to the most compact form
        appropriate and available.

        If ``x`` is some other type of :py:class:`Packet`, it will be stacked
        on :py:class:`PPP` first (but may be converted to :py:class:`HDLC` or
        :py:class:`PPP_`).

        See :py:attr:`enable_pfc` and :py:attr:`enable_acfc`.

There are some helper methods for using PPP with a file-like object:

.. py:function:: ppp_socket(fd: file[, default_read_size: int]) \
                        -> PPPPacketizerSocket

    Wraps a PPP socket around a given file-like object.

    :param fd: A file-like object, or (integer) file descriptor
    :type fd: file or int
    :param int default_read_size: See :py:class:`PacketizerSocket`.

.. py:function:: ppp_pty([default_read_size: int]) \
                     -> tuple[PPPPacketizerSocket, str, int]

    Creates a virtual PTY using :py:func:`os.openpty`, and attaches a
    :py:func:`PacketizerSocket` to it.

