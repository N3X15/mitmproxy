import socket

from OpenSSL import SSL

import mitmproxy.net.udp
from mitmproxy import udp
from mitmproxy import flow
from mitmproxy import exceptions
from mitmproxy.proxy.protocol import base


class RawUDPLayer(base.Layer):
    chunk_size = 4096

    def __init__(self, ctx, ignore=False):
        self.ignore = ignore
        super().__init__(ctx)

    def __call__(self):
        self.connect()

        if not self.ignore:
            f = udp.UDPFlow(self.client_conn, self.server_conn, self)
            self.channel.ask("udp_start", f)

        buf = memoryview(bytearray(self.chunk_size))

        client = self.client_conn.connection
        server = self.server_conn.connection
        conns = [client, server]

        # https://github.com/openssl/openssl/issues/6234
        #for conn in conns:
        #    if isinstance(conn, SSL.Connection) and hasattr(SSL._lib, "SSL_clear_mode"):
        #        SSL._lib.SSL_clear_mode(conn._ssl, SSL._lib.SSL_MODE_AUTO_RETRY)

        try:
            while not self.channel.should_exit.is_set():
                r = mitmproxy.net.udp.read_select(conns, 10)
                for conn in r:
                    dst = server if conn == client else client
                    size = conn.recv_into(buf, self.chunk_size)
                    if not size:
                        conns.remove(conn)
                        # Shutdown connection to the other peer
                        dst.shutdown(socket.SHUT_WR)

                        if len(conns) == 0:
                            return
                        continue

                    udp_message = udp.UDPMessage(dst == server, buf[:size].tobytes())
                    if not self.ignore:
                        f.messages.append(udp_message)
                        self.channel.ask("udp_message", f)
                    dst.sendall(udp_message.content)

        except (OSError, exceptions.UdpException) as e:
            if not self.ignore:
                f.error = flow.Error("UDP connection closed unexpectedly: {}".format(repr(e)))
                self.channel.tell("udp_error", f)
        finally:
            if not self.ignore:
                self.channel.tell("udp_end", f)
