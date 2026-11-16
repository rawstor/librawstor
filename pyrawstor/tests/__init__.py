import atexit
import os
import tempfile

# Importing rawstor's Target and Location starts librawstor, which needs TLS
# settings. The tests work on local files and never open a TLS connection, but
# the settings have to be there and good: a CA of their own issues a
# certificate for the test process, before anything starts librawstor.
from rawstor import pki

_temp = tempfile.TemporaryDirectory(prefix="pyrawstor-pki-")
atexit.register(_temp.cleanup)

_ca = os.path.join(_temp.name, "ca")
_cert = os.path.join(_temp.name, "tests.crt")
_key = os.path.join(_temp.name, "tests.key")
pki.init(_ca, "pyrawstor tests CA")
pki.issue(_ca, "spiffe://pyrawstor.test/admin/tests", _cert, _key)

os.environ["RAWSTOR_TLS_TRUST_DOMAIN"] = "pyrawstor.test"
os.environ["RAWSTOR_TLS_CERT"] = _cert
os.environ["RAWSTOR_TLS_KEY"] = _key
os.environ["RAWSTOR_TLS_CA"] = pki.ca_file(_ca)
