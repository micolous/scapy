********************
TUN / TAP Interfaces
********************

.. note::

    This module only works on BSD, Linux and macOS.

TUN/TAP lets you create virtual network interfaces from userspace. There are two
types of devices:

TUN devices
    Operates at Layer 3 (:py:class:`IP`), and is generally limited to one
    protocol.

TAP devices
    Operates at Layer 2 (:py:class:`Ether`), and allows you to use any Layer 3
    protocol (:py:class:`IP`, :py:class:`IPv6`, IPX, etc.)

Using TUN/TAP in Scapy
======================

.. tip::

    Using TUN/TAP generally requires running Scapy (and these utilities) as
    ``root``.

:py:class:`TunTapInterface` lets you easily create a new device:

.. code-block:: pycon3

    >>> t = TunTapInterface('tun0')

You'll then need to bring the interface up, and assign an IP address in another
terminal.

Because TAP is a layer 3 connection, it acts as a point-to-point link.  We'll
assign these parameters:

local address (for your machine)
    192.0.2.1

remote address (for Scapy)
    192.0.2.2

On Linux, you would use:

.. code-block:: console

    # ip link set tun0 up
    # ip addr add 192.0.2.1 peer 192.0.2.2 dev tun0

On BSD and macOS, use:

.. code-block:: console

    # ifconfig tun0 up
    # ifconfig tun0 192.0.2.1 192.0.2.2

Now, nothing will happen when you ping those addresses -- you'll need to make
Scapy respond to that traffic.

:py:class:`TunTapInterface` works the same as a :py:class:`SuperSocket`, so lets
setup an :py:class:`AnsweringMachine` to respond to :py:class:`ICMP`
``echo-request``:

.. code-block:: pycon3

    >>> am = t.am(ICMPEcho_am)
    >>> am()

Now, you can ping Scapy in another terminal:

.. code-block: console:

    $ ping -c 3 192.0.2.2
    PING 192.0.2.2 (192.0.2.2): 56 data bytes
    64 bytes from 192.0.2.2: icmp_seq=0 ttl=64 time=2.414 ms
    64 bytes from 192.0.2.2: icmp_seq=1 ttl=64 time=3.927 ms
    64 bytes from 192.0.2.2: icmp_seq=2 ttl=64 time=5.740 ms

    --- 192.0.2.2 ping statistics ---
    3 packets transmitted, 3 packets received, 0.0% packet loss
    round-trip min/avg/max/stddev = 2.414/4.027/5.740/1.360 ms

You should see those packets show up in Scapy:

.. code-block:: pycon3

    >>> am()
    Replying 192.0.2.1 to 192.0.2.2
    Replying 192.0.2.1 to 192.0.2.2
    Replying 192.0.2.1 to 192.0.2.2

You might have noticed that didn't configured any IP address inside of Scapy
itself... and there's a little trick to this:

:py:class:`ICMPEcho_am` will automatically swap the ``source`` and
``destination`` fields of any :py:class:`Ether` and :py:class:`IP` headers on
the :py:class:`ICMP` packet.

You can stop the AnsweringMachine with :kbd:`^C`.

When you close Scapy, the ``tun0`` interface will automatically disappear.
