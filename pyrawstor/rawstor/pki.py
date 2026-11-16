"""A small certificate authority for a cluster that has none.

It makes the files a process needs to speak TLS: ``ca.crt`` of the CA, which
the process lists as ``RAWSTOR_TLS_CA``, and a certificate and a key of its own
for ``RAWSTOR_TLS_CERT`` and ``RAWSTOR_TLS_KEY``. Importing this module does not
start rawstor, so it can run before the settings it makes are in place.

Every function raises ``OSError`` (``FileExistsError`` for an ``init`` over an
existing CA, ``FileNotFoundError`` for a CA or a certificate that is not
there, ``errno.EINVAL`` for a bad identity, a bad validity or a certificate
this CA did not issue).
"""

import datetime
import os
from typing import Union

from . import libpki

Validity = Union[datetime.timedelta, int]

CA_VALIDITY = datetime.timedelta(days=3650)
VALIDITY = datetime.timedelta(days=7)


def _seconds(validity: Validity) -> int:
    if isinstance(validity, datetime.timedelta):
        validity = int(validity.total_seconds())
    if validity <= 0:
        raise OSError(22, "The validity must be positive")
    return validity


def init(
    directory: Union[str, "os.PathLike[str]"],
    name: str = "rawstor CA",
    validity: Validity = CA_VALIDITY,
) -> None:
    """Creates ``directory`` (mode 0700) with a new CA: ``ca.crt`` and
    ``ca.key``."""
    libpki.init(os.fspath(directory), name, _seconds(validity))


def ca_file(directory: Union[str, "os.PathLike[str]"]) -> str:
    """The CA certificate of the CA in ``directory``: ``RAWSTOR_TLS_CA``."""
    return os.path.join(os.fspath(directory), "ca.crt")


def issue(
    directory: Union[str, "os.PathLike[str]"],
    identity: str,
    cert_file: Union[str, "os.PathLike[str]"],
    key_file: Union[str, "os.PathLike[str]"],
    validity: Validity = VALIDITY,
) -> None:
    """Issues a certificate and a new private key for ``identity``, a SPIFFE
    ID such as ``spiffe://cluster.example/ost/<uuid>``, replacing the files."""
    libpki.issue(
        os.fspath(directory),
        identity,
        _seconds(validity),
        os.fspath(cert_file),
        os.fspath(key_file),
    )


def renew(
    directory: Union[str, "os.PathLike[str]"],
    cert_file: Union[str, "os.PathLike[str]"],
    key_file: Union[str, "os.PathLike[str]"],
    validity: Validity = VALIDITY,
) -> None:
    """Issues a new certificate and key for the identity of ``cert_file``,
    which this CA must have issued, over the same files."""
    libpki.renew(
        os.fspath(directory),
        os.fspath(cert_file),
        os.fspath(key_file),
        _seconds(validity),
    )
