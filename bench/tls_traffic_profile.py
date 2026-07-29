"""The traffic this benchmark sends: TLS connections carrying a hostname we choose.

WHAT THIS FILE IS
    A TRex ASTF profile. TRex loads it, and it describes every connection the
    generator will make: how many per second, which addresses, and the exact
    bytes each side sends.

WHY IT EXISTS AT ALL
    PacketInspector decides whether to block a connection by reading the
    hostname out of the TLS ClientHello -- the SNI extension. To measure that,
    the traffic has to actually contain one. Nothing shipped with TRex does:

      * astf/http_simple.py is plain HTTP, so every flow resolves to "not TLS"
        and the inspector never reaches hostname extraction at all.
      * avl/delay_10_https_0.pcap is a real TLS capture, but from around 2010,
        before SNI was in common use.

    Measuring a hostname blocker against either one measures TCP reassembly and
    nothing else. So the ClientHello is built here, byte by byte. That also
    means the hostname is a parameter rather than whatever a capture happened
    to contain, which is what makes a known blocked/allowed ratio possible.

HOW THE BLOCKED RATIO WORKS
    Two connection templates, told apart by destination port so the server side
    knows which script to run:

        port 443    ALLOWED_HOSTNAME    expected to complete normally
        port 8443   BLOCKED_HOSTNAME    expected to be blocked

    --block-packet-ratio sets the split: 0.2 means 20% of connections aim at
    the blocked hostname. 0.0 and 1.0 are useful as sanity checks.

WHAT TO EXPECT WHEN BLOCKING WORKS
    Blocked connections do not finish, and that is the correct outcome rather
    than a fault. Once the inspector blocks a flow it drops every packet of it,
    including the client's FIN, so the connection stays open until TCP gives
    up. Those show up in the generator's counters as timeouts and inflate the
    active-flow count. Read throughput against the allowed share; read the
    blocked share as a correctness signal. If blocked connections start
    completing as load rises, hostnames are getting through unchecked.
"""

import argparse
import os
import struct

# TRex's classes are imported inside the methods that build the profile, not at
# module level. That keeps this file importable by the rest of the benchmark --
# which only wants the two hostnames below -- without TRex being on the path.

# These two names are also written into the blocklist by packet_inspector.py.
# Exact matches rather than wildcards, so a parsing slip cannot quietly become
# a match and make blocking look better than it is.
ALLOWED_HOSTNAME = "allowed.bench.test"
BLOCKED_HOSTNAME = "blocked.bench.test"

ALLOWED_PORT = 443
BLOCKED_PORT = 8443

# Template group names. TRex reports counters separately per group, which is the
# only way to see what happened to the blocked connections specifically. The
# aggregate numbers cannot show it: blocking happens at the ClientHello, after
# the TCP handshake has already completed, so a blocked connection still counts
# as established. What distinguishes it is that it never receives the server's
# reply -- and that is only visible per group.
ALLOWED_GROUP = "allowed"
BLOCKED_GROUP = "blocked"


def build_client_hello(hostname: str) -> bytes:
    """Construct a TLS 1.2 ClientHello whose SNI extension carries `hostname`.

    Laid out to satisfy the parser in src/hostname_extractor.cpp, which walks:

        record header (5 bytes, must start 0x16 0x03)
        handshake header (4 bytes, type must be 0x01)
        legacy_version (2) + random (32)
        session_id      (1 length byte + that many)
        cipher_suites   (2 length bytes + that many)
        compression     (1 length byte + that many)
        extensions      (2 length bytes, then type/length/value entries)

    and then looks for extension type 0x0000, server_name.

    Padded to roughly the size of a real ClientHello (a browser sends 300-500
    bytes) so the packet count per connection is realistic, but only the fields
    listed above have to be correct -- the inspector reads nothing else.
    """
    name = hostname.encode()

    # server_name extension body: list_length(2) name_type(1) name_length(2) name
    server_name_body = struct.pack("!HBH", len(name) + 3, 0x00, len(name)) + name
    server_name_ext = struct.pack("!HH", 0x0000, len(server_name_body)) + server_name_body

    # A padding extension (type 0x0015) brings the message up to a realistic
    # size without inventing extensions that would need to mean something.
    padding = b"\x00" * 200
    padding_ext = struct.pack("!HH", 0x0015, len(padding)) + padding

    extensions = server_name_ext + padding_ext

    body = (
        b"\x03\x03"                          # legacy_version: TLS 1.2
        + os.urandom(32)                     # random
        + b"\x00"                            # session_id length: none
        + struct.pack("!H", 4)               # cipher_suites length
        + b"\x13\x01\xc0\x2f"                # two plausible cipher suites
        + b"\x01\x00"                        # compression: one method, null
        + struct.pack("!H", len(extensions))
        + extensions
    )

    # Handshake header: type 0x01, then a 24-bit length.
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    # Record header: handshake content type, version, 16-bit length.
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def build_server_response(size: int = 1400) -> bytes:
    """The bytes the server sends back.

    Never inspected: the queue rule only captures the client-to-server
    direction, and a hostname only ever appears there. So this only has to be
    traffic of a realistic size, not valid TLS.
    """
    return b"\x16\x03\x03" + struct.pack("!H", size - 5) + os.urandom(size - 5)


class Prof1:
    """TRex requires this class name and the register() function below."""

    def get_profile(self, tunables, **kwargs):
        parser = argparse.ArgumentParser(
            description="TLS/SNI traffic for the PacketInspector benchmark")
        # Both spellings accepted on purpose. A person types
        # --block-packet-ratio; TRex builds the flag from the tunables
        # dictionary key, so it arrives as --block_packet_ratio.
        parser.add_argument("--block-packet-ratio", "--block_packet_ratio",
                            dest="block_packet_ratio", type=float, default=0.2,
                            help="fraction of connections aimed at the blocked "
                                 "hostname, 0.0 to 1.0")
        args = parser.parse_args(tunables)

        ratio = args.block_packet_ratio
        if not 0.0 <= ratio <= 1.0:
            raise ValueError(
                f"--block-packet-ratio must be between 0.0 and 1.0, got {ratio}")

        from trex.astf.api import (ASTFIPGen, ASTFIPGenDist, ASTFIPGenGlobal,
                                   ASTFProfile)

        # The same address ranges TRex's own profiles use, so the routes and
        # static ARP entries the topology installs keep working unchanged.
        ip_gen = ASTFIPGen(
            glob=ASTFIPGenGlobal(ip_offset="1.0.0.0"),
            dist_client=ASTFIPGenDist(
                ip_range=["16.0.0.0", "16.0.0.255"], distribution="seq"),
            dist_server=ASTFIPGenDist(
                ip_range=["48.0.0.0", "48.0.255.255"], distribution="seq"))

        # Absolute rates here are only a base; the benchmark's -m multiplier
        # scales both templates together. Only the ratio between them matters.
        blocked_share = 100.0 * ratio
        allowed_share = 100.0 - blocked_share

        templates = []
        if allowed_share > 0:
            templates.append(self._make_template(
                ip_gen, ALLOWED_HOSTNAME, ALLOWED_PORT, allowed_share,
                ALLOWED_GROUP))
        if blocked_share > 0:
            templates.append(self._make_template(
                ip_gen, BLOCKED_HOSTNAME, BLOCKED_PORT, blocked_share,
                BLOCKED_GROUP))

        return ASTFProfile(default_ip_gen=ip_gen, templates=templates)

    @staticmethod
    def _make_template(ip_gen, hostname: str, port: int, rate: float,
                       group: str):
        """One connection type: client sends a ClientHello, server replies."""
        from trex.astf.api import (ASTFAssociationRule, ASTFProgram,
                                   ASTFTCPClientTemplate, ASTFTCPServerTemplate,
                                   ASTFTemplate)

        client_hello = build_client_hello(hostname)
        response = build_server_response()

        client_script = ASTFProgram()
        client_script.send(client_hello)
        client_script.recv(len(response))

        server_script = ASTFProgram()
        server_script.recv(len(client_hello))
        server_script.send(response)

        return ASTFTemplate(
            client_template=ASTFTCPClientTemplate(
                program=client_script, ip_gen=ip_gen, port=port, cps=rate),
            server_template=ASTFTCPServerTemplate(
                program=server_script,
                assoc=ASTFAssociationRule(port=port)),
            tg_name=group)


def register():
    return Prof1()
