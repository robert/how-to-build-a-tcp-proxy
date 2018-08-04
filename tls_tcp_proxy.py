import time

from twisted.internet import protocol, reactor
from twisted.internet import ssl as twisted_ssl
import dns.resolver

from OpenSSL.crypto import (X509Extension, X509,
        dump_privatekey, dump_certificate,
        load_certificate, load_privatekey,
        PKey, TYPE_RSA, X509Req)
from OpenSSL.SSL import FILETYPE_PEM
import tempfile
import os
import netifaces as ni
 
# Adapted from http://stackoverflow.com/a/15645169/221061

class TLSTCPProxyProtocol(protocol.Protocol):
    """
    TLSTCPProxyProtocol listens for TCP connections from a
    client (eg. a phone) and forwards them on to a specified
    destination (eg. an app's API server) over a second TCP
    connection, using a ProxyToServerProtocol.

    It assumes that both legs of this trip are encrypted
    using TLS.
    """
    def __init__(self):
        self.buffer = None
        self.proxy_to_server_protocol = None
 
    def connectionMade(self):
        """
        Called by twisted when a client connects to the
        proxy.  Makes an TLS connection from the proxy to
        the server to complete the chain.
        """
        print("Connection made from CLIENT => PROXY")
        proxy_to_server_factory = protocol.ClientFactory()
        proxy_to_server_factory.protocol = ProxyToServerProtocol
        proxy_to_server_factory.server = self
 
        reactor.connectSSL(DST_IP, DST_PORT,
                           proxy_to_server_factory,
                           twisted_ssl.CertificateOptions())
 
    def dataReceived(self, data):
        """
        Called by twisted when the proxy receives data from
        the client. Sends the data on to the server.

        CLIENT ===> PROXY ===> DST
        """
        print("")
        print("CLIENT => SERVER")
        print(FORMAT_FN(data))
        WRITE_TO_FILE(data)
        print("")
        if self.proxy_to_server_protocol:
            self.proxy_to_server_protocol.write(data)
        else:
            self.buffer = data
 
    def write(self, data):
        self.transport.write(data)
 
 
class ProxyToServerProtocol(protocol.Protocol):
    """
    ProxyToServerProtocol connects to a server over TCP.
    It sends the server data given to it by an
    TLSTCPProxyProtocol, and uses the TLSTCPProxyProtocol
    to send data that it receives back from the server on
    to a client.
    """

    def connectionMade(self):
        """
        Called by twisted when the proxy connects to the
        server.  Flushes any buffered data on the proxy
        to server.
        """
        print("Connection made from PROXY => SERVER")
        self.factory.server.proxy_to_server_protocol = self
        self.write(self.factory.server.buffer)
        self.factory.server.buffer = ''
 
    def dataReceived(self, data):
        """
        Called by twisted when the proxy receives data
        from the server. Sends the data on to to the
        client.

        DST ===> PROXY ===> CLIENT
        """
        print("")
        print("SERVER => CLIENT")
        print(FORMAT_FN(data))
        print("")
        self.factory.server.write(data)
 
    def write(self, data):
        if data:
            self.transport.write(data)


# A class that represents a CA. It wraps a root CA TLS
# certificate, and can generate and sign certificates using
# this root cert.
#
# Inpsiration from
# https://github.com/allfro/pymiproxy/blob/master/src/miproxy/proxy.py
class CertificateAuthority(object):

    CERT_PREFIX = 'fake-cert'

    def __init__(self, ca_file, cache_dir=tempfile.mkdtemp()):
        print("Initializing CertificateAuthority ca_file=%s cache_dir=%s" %
              (ca_file, cache_dir))

        self.ca_file = ca_file
        self.cache_dir = cache_dir
        if not os.path.exists(ca_file):
            raise Exception("No cert exists at %s" % ca_file)
        else:
            self._read_ca(ca_file)

    def get_cert_path(self, cn):
        cnp = os.path.sep.join([self.cache_dir, '%s-%s.pem' %
            (self.CERT_PREFIX, cn)])
        if os.path.exists(cnp):
            print("Cert already exists common_name=%s" % cn)
        else:
            print("Creating and signing cert common_name=%s" % cn)
            key = PKey()
            key.generate_key(TYPE_RSA, 2048)

            # Generate CSR
            req = X509Req()
            req.get_subject().CN = cn
            req.set_pubkey(key)
            req.sign(key, 'sha1')

            # Sign CSR
            cert = X509()
            cert.set_subject(req.get_subject())
            cert.set_serial_number(123)
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(31536000)
            cert.set_issuer(self.cert.get_subject())
            cert.set_pubkey(req.get_pubkey())
            cert.sign(self.key, 'sha1')

            with open(cnp, 'wb+') as f:
                f.write(dump_privatekey(FILETYPE_PEM, key))
                f.write(dump_certificate(FILETYPE_PEM, cert))

            print("Created cert common_name=%s location=%s" % (cn, cnp))

        return cnp

    def _read_ca(self, file):
        self.cert = load_certificate(FILETYPE_PEM, open(file).read())
        self.key = load_privatekey(FILETYPE_PEM, open(file).read())

    @staticmethod
    def generate_ca_cert(path, common_name):
        if os.path.exists(path):
            print("Cert already exists at %s, not regenerating" % path)
            return
        # Generate key
        key = PKey()
        key.generate_key(TYPE_RSA, 2048)

        # Generate certificate
        cert = X509()
        cert.set_version(3)
        cert.set_serial_number(1)
        cert.get_subject().CN = common_name
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(315360000)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, "sha256")

        with open(path, 'wb+') as f:
            f.write(dump_privatekey(FILETYPE_PEM, key))
            f.write(dump_certificate(FILETYPE_PEM, cert))


def get_local_ip(iface):
    ni.ifaddresses(iface)
    return ni.ifaddresses(iface)[ni.AF_INET][0]['addr']


# Alternative functions for formating output data
def _side_by_side_hex(data):
    BLOCK_SIZE = 16

    output_lines = []
    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i+BLOCK_SIZE]
        _hex = ["%.2x" % el for el in block]
        _str = [chr(el) if chr(el).isprintable() else "." for el in block]
        line = " ".join(_hex).ljust((3*BLOCK_SIZE)+4) + "".join(_str).replace("\n", ".")
        output_lines.append(line)
    return "\n".join(output_lines)

def _stacked_hex(data):
    BLOCK_SIZE = 32

    hex_lines = []
    plaintext_lines = []
    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i+BLOCK_SIZE]
        _hex = ["%.2x" % el for el in block]
        _str = [chr(el) if chr(el).isprintable() else "." for el in block]

        hex_line = " ".join(_hex)
        hex_lines.append(hex_line)

        plaintext_line = "  ".join(_str).replace("\n", ".")
        plaintext_lines.append(plaintext_line)

    lines = hex_lines + ["\n"] + plaintext_lines
    return "\n".join(lines)

def _replayable(data):
    d = data[0:4000]
    _hex = "".join(["%.2x" % el for el in d])
    _str = "".join([chr(el) if chr(el).isprintable() else "." for el in d])

    return _hex + "\n" + _str

def _noop(data):
    return data

# Change this line to use an alternative formating function
FORMAT_FN = _noop

# Record data sent to the server to files
DIR_NAME = "replays/messages-%d/" % time.time()
os.mkdir(DIR_NAME)
f_n = 0
def _write_to_file(data):
    # Global variables are bad but they do the job
    global f_n
    with open(DIR_NAME + str(f_n), 'wb') as f:
        f.write(data)
        f_n += 1
WRITE_TO_FILE = _write_to_file

CA_CERT_PATH = "./ca-cert.pem"

LISTEN_PORT = 443
DST_PORT = 443
DST_HOST = "www.bbc.com"
local_ip = get_local_ip('en0')

print("Querying DNS records for %s..." % DST_HOST)
a_records = dns.resolver.query(DST_HOST, 'A')
print("Found %d A records:" % len(a_records))
for r in a_records:
    print("* %s" % r.address)
print("")
assert(len(a_records) > 0)

DST_IP = a_records[0].address
print("Choosing to proxy to %s" % DST_IP)

print("""
#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#
-#-#-#-#-#-RUNNING TLS TCP PROXY-#-#-#-#-#-
#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#

Root CA path:\t%s

Dst IP:\t%s
Dst port:\t%d
Dst hostname:\t%s

Listen port:\t%d
Local IP:\t%s
""" % (CA_CERT_PATH, DST_IP, DST_PORT, DST_HOST, LISTEN_PORT, local_ip))
 
CertificateAuthority.generate_ca_cert(CA_CERT_PATH, "Robert's Trusty Certificate Corp")
ca = CertificateAuthority(CA_CERT_PATH)
certfile = ca.get_cert_path(DST_HOST)
with open(certfile) as f:
    cert = twisted_ssl.PrivateCertificate.loadPEM(f.read())

print("""
Next steps:

1. Make sure you are spoofing DNS requests from the
device you are trying to proxy request from so that they
return your local IP (%s).
2. Make sure you have set the destination and listen
ports correctly (they should generally be the same).
3. Use the device you are proxying requests from to make
requests to %s and check that they are logged in this
terminal.
4. Look at the requests, write more code to replay them,
fiddle with them, etc.

Listening for requests on %s:%d...
""" % (local_ip, DST_HOST, local_ip, LISTEN_PORT))

factory = protocol.ServerFactory()
factory.protocol = TLSTCPProxyProtocol
reactor.listenSSL(LISTEN_PORT, factory, cert.options(),
                  interface=local_ip)
reactor.run()
