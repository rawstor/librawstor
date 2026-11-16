"""A small certificate authority for a cluster that has none.

It makes the files a process needs to speak TLS: ``ca.crt`` of the CA, which
the process lists as ``RAWSTOR_TLS_CA``, and a certificate and a key of its own
for ``RAWSTOR_TLS_CERT`` and ``RAWSTOR_TLS_KEY``. A CA serves one cluster, whose
trust domain (``RAWSTOR_TLS_TRUST_DOMAIN``) it is made for, and every certificate
it issues is in that trust domain. Importing this module does not start rawstor,
so it can run before the settings it makes are in place.

Every function raises ``OSError`` (``FileExistsError`` for an ``init`` over an
existing CA, ``FileNotFoundError`` for a CA or a certificate that is not
there, ``errno.EINVAL`` for a bad trust domain, a bad name, a bad validity or a
certificate this CA did not issue).
"""

import datetime
import os
from typing import Dict, Mapping, NamedTuple, Optional, Union

from . import libpki

Path = Union[str, "os.PathLike[str]"]
Validity = Union[datetime.timedelta, int]

CA_VALIDITY = datetime.timedelta(days=3650)
VALIDITY = datetime.timedelta(days=7)

# RawstorPkiRole in <rawstor/pki.h>.
_OST = 0
_MDS = 1
_ADMIN = 2
_CLIENT = 3


def _seconds(validity: Validity) -> int:
    if isinstance(validity, datetime.timedelta):
        validity = int(validity.total_seconds())
    if validity <= 0:
        raise OSError(22, "The validity must be positive")
    return validity


def init(
    directory: Path,
    trust_domain: str,
    validity: Validity = CA_VALIDITY,
) -> None:
    """Creates ``directory`` (mode 0700) with a new CA for ``trust_domain``:
    ``ca.crt``, ``ca.key`` and ``trust_domain``."""
    libpki.init(os.fspath(directory), trust_domain, _seconds(validity))


def ca_file(directory: Path) -> str:
    """The CA certificate of the CA in ``directory``: ``RAWSTOR_TLS_CA``."""
    return os.path.join(os.fspath(directory), "ca.crt")


def _issue(
    directory: Path,
    role: int,
    tenant: Optional[str],
    name: Optional[str],
    cert_file: Path,
    key_file: Path,
    validity: Validity,
    access_role: int = 0,
    object_permissions: Optional[Mapping[str, int]] = None,
) -> str:
    return libpki.issue(
        os.fspath(directory),
        role,
        tenant,
        name,
        _seconds(validity),
        os.fspath(cert_file),
        os.fspath(key_file),
        access_role,
        None if object_permissions is None else dict(object_permissions),
    )


def issue_ost(
    directory: Path,
    cert_file: Path,
    key_file: Path,
    ost_id: Optional[str] = None,
    validity: Validity = VALIDITY,
) -> str:
    """Issues a certificate and a new private key for a rawstor-ost, replacing
    the files. ``ost_id`` is its id in the MDS topology, a UUID; a new one is
    made without it. Returns the SPIFFE ID the certificate names."""
    return _issue(directory, _OST, None, ost_id, cert_file, key_file, validity)


def issue_mds(
    directory: Path,
    cert_file: Path,
    key_file: Path,
    mds_id: Optional[str] = None,
    validity: Validity = VALIDITY,
) -> str:
    """Issues a certificate and a key for a rawstor-mds. ``mds_id`` is its id,
    a UUID like an OST's; a new one is made without it. Returns the SPIFFE ID
    the certificate names."""
    return _issue(directory, _MDS, None, mds_id, cert_file, key_file, validity)


def issue_admin(
    directory: Path,
    name: str,
    cert_file: Path,
    key_file: Path,
    validity: Validity = VALIDITY,
) -> str:
    """Issues a certificate and a key for an operator or a control plane
    called ``name``."""
    return _issue(directory, _ADMIN, None, name, cert_file, key_file, validity)


def issue_client(
    directory: Path,
    tenant: str,
    name: str,
    cert_file: Path,
    key_file: Path,
    validity: Validity = VALIDITY,
    *,
    role: str,
    object_permissions: Optional[Mapping[str, int]] = None,
) -> str:
    """Issue tenant credentials with a none, reader, writer or manager role.

    Object masks override the role for each named UUID, including its versions;
    zero denies access. Other objects retain the role's permissions.
    """
    roles = {"none": 0, "reader": 1, "writer": 2, "manager": 3}
    if role not in roles:
        raise ValueError("role must be none, reader, writer or manager")
    return _issue(directory, _CLIENT, tenant, name, cert_file, key_file, validity,
                  roles[role], object_permissions)


class Info(NamedTuple):
    """What a certificate says."""

    #: The SPIFFE ID of the process it is for.
    identity: str
    #: When it expires.
    not_after: datetime.datetime
    #: Whether the CA given to ``show()`` signed it, None without a CA.
    issued: Optional[bool]
    access_role: Optional[str]
    object_permissions: Dict[str, int]


def show(cert_file: Path, directory: Optional[Path] = None) -> Info:
    """Reads the certificate ``cert_file`` of a process, whoever issued it; it
    changes nothing. With ``directory``, a CA, ``issued`` tells whether that CA
    signed it, without needing its private key. Raises ``OSError`` (``errno.EINVAL``) for a file that is not a
    certificate that names a process of rawstor."""
    identity, not_after, issued, access_role, object_permissions = libpki.show(
        os.fspath(cert_file),
        None if directory is None else os.fspath(directory),
    )
    return Info(
        identity,
        datetime.datetime.fromtimestamp(not_after, datetime.timezone.utc),
        issued,
        ({0: "none", 1: "reader", 2: "writer", 3: "manager"}[access_role]
         if "/tenant/" in identity else None),
        object_permissions,
    )


def renew(
    directory: Path,
    cert_file: Path,
    key_file: Path,
    validity: Validity = VALIDITY,
) -> str:
    """Issues a new certificate and key for the process ``cert_file`` was
    issued for, which this CA must have issued, over the same files. Returns
    the SPIFFE ID."""
    return libpki.renew(
        os.fspath(directory),
        os.fspath(cert_file),
        os.fspath(key_file),
        _seconds(validity),
    )
