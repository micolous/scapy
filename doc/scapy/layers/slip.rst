*********************
SLIP (Serial Line IP)
*********************

Serial Line IP (:rfc:`1055`) is a `data link layer`__ protocol for passing
packets over a serial link.

__ https://en.wikipedia.org/wiki/Data_link_layer

Despite the name, there is no requirement that the protocol be used for IPv4
packets.  However, the protocol itself has no mechanism for negotiating the
protocol used.

.. _slip-encap:

The protocol itself is very simple:

``end``
  The sequence used to terminate each packet (default: ``C0``)

``esc``
  The sequence that precedes all escape sequences (default: ``DB``)

Then, any use of the ``end`` or ``esc`` byte are escaped in two special escape
sequences, which are preceded with ``esc``:

``end_esc``
  The sequence used to encode a literal ``end`` in the packet (default: ``DC``)

``esc_esc``
  The sequence used to encode a literal ``esc`` in the packet (default: ``DD``)

Some protocols similar to SLIP define:

``start``
  The sequence used to start each packet.

``start_esc``
  The sequence used to encode a literal ``start`` in the packet.

:py:class:`SLIPPacketizer` also supports both single-byte (used by :rfc:`1055`)
and multi-byte sequences (used by some variants) for all parameters.

.. seealso::

    :rfc:`1055`
        Defines the Serial Line IP protocol.

    :doc:`PPP (Point to Point Protocol) <ppp>`
        A similar, but more complex protocol for transmitting packets over
        serial links.

    :ref:`Packetizers in Scapy <packetizers>`
        Explains how the :py:class:`Packetizer` interface works in Scapy.

Creating a SLIP connection
==========================

This example sets up a Serial Line IP connection with IPv4, between Scapy and a
remote host.

There are two methods described here, which have different requirements:

using a real serial port
  This requires that you install the `PySerial`__ library, and that you have
  connected two hosts (or the same host on two ports) with a `null modem
  cable`__.

__ https://github.com/pyserial/pyserial
__ https://en.wikipedia.org/wiki/Null_modem

using a virtual PTY
  This will use your local machine's kernel as the "remote" host, and make Scapy
  appear as a network interface.

  .. tip::

      If you want to attach Scapy to a local, virtual network interface, use
      :py:class:`TunTapInterface`` -- this is easier to use and more widely
      available.

      This is only described in this section as an example, and to allow you to
      test Scapy without needing an actual serial port.

In both cases, your "remote" host will also need a SLIP client:

  * On Linux, you'll need the :command:`slattach` tool, which is part of the
    (mostly obsolete) ``net-tools`` package.

  * Mac OS X does not support SLIP natively -- you'll need to use a tool like
    `slip2tun`__ to attach it to a userspace ``tuntap`` device.

  * Windows 95 through to XP support SLIP natively.

  * Windows Vista and later do not support SLIP.

__ https://github.com/antoinealb/serial-line-ip-osx

This will be a point-to-point link, with these addresses:

  * Scapy IP address: ``192.0.2.1``
  * Remote IP address: ``192.0.2.2``

To start, we'll create an ICMP Echo Request packet (ping), and add some
fuzzing to the frame in order make sure we get random sequence numbers:

.. code-block:: python3

    echo = (IP(src='192.0.2.1', dst='192.0.2.2')/
            ICMP(type='echo-request')/
            Raw(b'hello!'))

    fuzz(echo[ICMP], 1)

The second parameter to ``fuzz`` causes the operation to be done in-place. This
causes the packet to become volatile -- causing it change every time it is
serialized:

.. code-block:: pycon

    >>> bytes_hex(echo)
    b'45000022000100004001f6d6c0000201c00002020800d44551b68e1068656c6c6f21'
    >>> bytes_hex(echo)
    b'45000022000100004001f6d6c0000201c000020208b84ab6ffc368da68656c6c6f21'
    >>> bytes_hex(echo)
    b'45000022000100004001f6d6c0000201c00002020863d2caeba9f53468656c6c6f21'
    >>> bytes_hex(echo)
    b'45000022000100004001f6d6c0000201c00002020812f5faa577188868656c6c6f21'

Now, we can create the SLIP link!

For a real serial port,
  use :py:func:`slip_connect`, with:

  .. code-block:: pycon

      >>> sock = slip_connect('/dev/ttyS0', 9600)

  You will need to replace ``/dev/ttyS0`` with the actual serial port you want
  to use, and ``9600`` with the actual baud rate you want to use.

``slip_connect`` returns a ``PacketizerSocket``.

For a virtual PTY,
  use :py:func:`slip_pty`. This automatically opens a new PTY, and reports back
  the name of it for you to use:

  .. code-block:: pycon

      >>> s, child_fn, child_fd = slip_pty()
      >>> child_fn
      /dev/pts/6        # example for Linux
      /dev/ttys006      # example for OSX

  This will give you a path to the child PTY on ``child_fn``, and the file
  descriptor number in ``child_fd``. The parent PTY is part of the
  ``PacketizerSocket`` (in ``sock``).

**Now that you have a port,** you now need to setup a SLIP client on the other
end of it:

For Linux, these commands will need to be run as root:

.. code-block:: bash

    modprobe -v slip

    # Pick one of these options:
    slattach -s 9600 /dev/ttyS0     # for a physical port
    slattach /dev/pts/6             # for a virtual port

    # Now set an IP and bring it up:
    ip addr change 192.0.2.2/32 peer 192.0.2.1 dev sl0
    ip link set sl0 up

For OSX, these commands will need to be run as root:

.. code-block:: bash

    # Note: there should be no output from this command, and the tunnel will
    # become live immediately.
    slip2tun -p /dev/ttys006 -l 192.0.2.2 -r 192.0.2.1

You can then start pinging the remote host from Scapy with:

.. code-block:: pycon

    >>> scapy.sendrecv.__sr_loop(pty.sr, [echo])
    RECV 1: IP / ICMP 192.0.2.2 > 192.0.2.1 echo-reply 239 / Raw
    RECV 1: IP / ICMP 192.0.2.2 > 192.0.2.1 echo-reply 22 / Raw
    RECV 1: IP / ICMP 192.0.2.2 > 192.0.2.1 echo-reply 36 / Raw

You can then stop pinging with :kbd:`^C`.

You may have tried to ping Scapy back, but that won't work yet, as there's
nothing configured to answer it yet! ``ICMPEcho_am`` is a basic
``AnsweringMachine`` that responds to ping requests:

.. code-block:: pycon

    >>> am = sock.am(ICMPEcho_am)
    >>> am()

Then, in another terminal, you can start pinging Scapy with:

.. code-block:: console

    $ ping -c 3 192.0.2.1
    PING 192.0.2.1 (192.0.2.1): 56 data bytes
    64 bytes from 192.0.2.1: icmp_seq=0 ttl=64 time=2.415 ms
    64 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=3.610 ms
    64 bytes from 192.0.2.1: icmp_seq=2 ttl=64 time=3.715 ms

    --- 192.0.2.1 ping statistics ---
    3 packets transmitted, 3 packets received, 0.0% packet loss
    round-trip min/avg/max/stddev = 2.415/3.247/3.715/0.590 ms

Switching back to Scapy, you should see the responses being sent:

.. code-block:: pycon

    >>> am()
    Replying 192.0.2.2 to 192.0.2.1
    Replying 192.0.2.2 to 192.0.2.1
    Replying 192.0.2.2 to 192.0.2.1

You can press :kbd:`^C` to stop the ``AnsweringMachine``.

When you're done, on Linux, take down the interface:

.. code-block:: bash

    ip link set sl0 down

And then press :kbd:`^C` in the terminal running ``slattach`` or ``slip2tun``.

Utility functions
=================

.. py:function:: slip_socket(fd, [packet_class: Type[Packet] = Raw], [default_read_size: int]) -> PacketizerSocket

   Creates a :py:class:`PacketizerSocket` that implements :rfc:`1055` SLIP.

   If ``packet_class`` is not specified, payloads are presumed to be
   :py:class:`Raw`.

   If ``fd`` is a Text or int type, then it is presumed to be a path to a file
   or a file descriptor number, respectively.

.. py:function:: slip_ipv4_socket(fd, [default_read_size: int]) -> PacketizerSocket

   Creates a :py:class:`PacketizerSocket` that implements :rfc:`1055` SLIP,
   where the payload is always :py:class:`IP` (IPv4).

   If ``fd`` is a Text or int type, then it is presumed to be a path to a file
   or a file descriptor number, respectively.

.. py:function:: slip_serial(port: Text, [baudrate: int = 9600], [timeout: int = 0], [packet_class: Type[Packet] = IP]) -> PacketizerSocket

   Creates a :py:class:`PacketizerSocket` that implements :rfc:`1055` SLIP,
   using ``pyserial`` to connect to a serial port.

   If ``packet_class`` is not specified, assumes :py:class:`IP` (IPv4) payloads.

.. py:function:: slip_pty([packet_class: Type[Packet] = IP]) -> Tuple[PacketizerSocket, Text, int]

   Creates a :py:class:`PacketizerSocket` that implements :rfc:`1055` SLIP,
   connected to a new PTY (created with :py:func:`os.openpty`).

   If ``packet_class`` is not specified, assumes :py:class:`IP` (IPv4) payloads.

   The return value is a tuple of:

   ``socket`` (PacketizerSocket)
     The :py:class:`PacketizerSocket` that is connected to the parent PTY.

   ``child_fn`` (Text)
     The path to the child PTY.

   ``child_fd`` (int)
     The file descriptor number for the child PTY.

.. _slip-api:

SLIPPacketizer API
==================

:py:class:`SLIPPacketizer` extends :py:class:`Packetizer`, and also provides a
base for similar protocols.

.. py:class:: SLIPPacketizer(Packetizer)

   SLIPPacketizer implements :rfc:`1055` Serial Line IP.

   It also acts as a base for simple :py:class:`Packetizer` types.

   .. py:method:: __init__(esc, esc_esc, end, end_esc, start, start_esc)

      All parameters are defined per :ref:`SLIP encapsulation <slip-encap>`
      (above).

      All parameters are required, except for ``start`` and ``start_esc``.

      All parameters are available as attributes on this class.

      :raises ValueError: on invalid configurations

   .. py:method:: handle_escape(i: int, end_msg_pos: int) -> Tuple[int, Optional[bytes]]

      :param int i: The position immediately after the end of the ``esc``
          sequence.
      :param int end_msg_pos: The number of bytes in the entire frame.

      Called whenever :py:meth:`.decode_frame` detects an ``esc`` sequence.

      This returns a tuple of:

      ``new_i`` (int)
        The position where we should continue reading from (i + the number of
        bytes that this method read from :py:attr:`Packetizer.buffer`)

        Returning ``i`` indicates that the next byte should be processed the
        same as any other byte.

      ``o`` (bytes or None)
        The decoded form of the escape sequence that was read.

        Return ``None`` to stop processing of the frame (eg: if reading the
        escape sequence would go beyond ``end_msg_pos``).

      Most simple protocols need not override this -- this is only useful if
      the protocol implements additional types of escapes that need to be
      decoded on input.

      Overriding this only impacts decoding packets, and does not impact
      encoding packets. Subclasses will need to implement
      :py:class:`Packetizer.encode_frame` if additional escapes are required.

      See :py:class:`PPPPacketizer` in :file:`scapy/layers/ppp.py` for an
      example of this in action.

Example subclass of SLIPPacketizer
----------------------------------

This example uses both start and end delimiters:

.. code-block:: python3

   class MyPacketizer(SLIPPacketizer):
       def __init__(self):
           super(MyPacketizer, self).__init__(
               esc=b'\xfe', esc_esc=b'\x02',
               end=b'\xff', end_esc=b'\x01',
               start=b'\xfd', start_esc=b'\x03')

This would make the packet ``FF 01 FE FD 02 03`` encode as:
``(FD) [FE 01] 01 [FE 02] [FE 03] 02 03 (FF)``
