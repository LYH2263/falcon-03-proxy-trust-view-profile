# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Declarative trust framing profiles for proxied request metadata."""

from __future__ import annotations

from collections.abc import Sequence

__all__ = ('TrustProfile',)

# Header identifiers are normalized to lowercase so that profiles may be
# declared using the same dash-separated names as the actual HTTP headers.
_FORWARDED = 'forwarded'
_X_FORWARDED_FOR = 'x-forwarded-for'
_X_REAL_IP = 'x-real-ip'
_X_FORWARDED_PROTO = 'x-forwarded-proto'
_X_FORWARDED_HOST = 'x-forwarded-host'

_ACCESS_ROUTE_CHOICES = frozenset((_FORWARDED, _X_FORWARDED_FOR, _X_REAL_IP))
_SCHEME_CHOICES = frozenset((_FORWARDED, _X_FORWARDED_PROTO))
_HOST_CHOICES = frozenset((_FORWARDED, _X_FORWARDED_HOST))

_DEFAULT_ACCESS_ROUTE_HEADERS = (
    _FORWARDED,
    _X_FORWARDED_FOR,
    _X_REAL_IP,
)
_DEFAULT_SCHEME_HEADERS = (_FORWARDED, _X_FORWARDED_PROTO)
_DEFAULT_HOST_HEADERS = (_FORWARDED, _X_FORWARDED_HOST)


def _validate_headers(
    headers: Sequence[str], choices: frozenset[str], what: str
) -> tuple[str, ...]:
    # NOTE: Normalize the declared header names to lowercase up front so that
    #   the hot request path can compare them without extra case folding.
    normalized = tuple(header.lower() for header in headers)

    if len(set(normalized)) != len(normalized):
        raise ValueError(
            f'{what} must not list the same header more than once: {headers!r}'
        )

    for header in normalized:
        if header not in choices:
            allowed = ', '.join(sorted(choices))
            raise ValueError(
                f'{what} contains unsupported header {header!r}; '
                f'allowed headers are: {allowed}'
            )

    return normalized


class TrustProfile:
    """Declarative trust framing profile for proxy-related request metadata.

    A trust profile declares how each of the four independent proxy trust
    chains of a :class:`~falcon.Request` frames the request headers that may
    be supplied by reverse proxies:

    1. The client chain behind :attr:`~falcon.Request.access_route`
       (``Forwarded``, ``X-Forwarded-For``, and ``X-Real-IP``).
    2. The RFC 7239 chain behind :attr:`~falcon.Request.forwarded`.
    3. The original scheme and host chains behind
       :attr:`~falcon.Request.forwarded_scheme` and
       :attr:`~falcon.Request.forwarded_host`.
    4. The recombined URI chains behind
       :attr:`~falcon.Request.forwarded_uri` and
       :attr:`~falcon.Request.forwarded_prefix`, which reuse the scheme and
       host chains together with their own caches.

    A profile is attached to a host via
    :attr:`falcon.RequestOptions.trust_profile`. Each Request snapshots the
    profile while it is being constructed, and subsequently fills its four
    caches according to that snapshot. Advancing the profile on the host
    only affects Requests that enter afterwards; Requests constructed under
    a previous profile keep both their profile label and their already
    observable values for the lifetime of the instance.

    Header names are matched case-insensitively. When a profile is not
    enabled (i.e. :attr:`~falcon.RequestOptions.trust_profile` is ``None``),
    the Request behaves exactly as it does without a profile.

    Note:
        Profiles are intended to be treated as immutable once shared with a
        host. Mutating a profile object that Requests already hold is not
        supported.

    Keyword Args:
        name (str | None): Human-readable label used to identify the profile
            (default ``None``). The label is not interpreted by Falcon.
        access_route_headers (Sequence[str]): Header names consulted, in
            order of preference, when framing :attr:`~falcon.Request.access_route`.
            Allowed values are ``'forwarded'``, ``'x-forwarded-for'``, and
            ``'x-real-ip'`` (default all three, in that order). The first
            header that is present wins; a malformed value is returned as
            parsed instead of falling through to the next header. An empty
            sequence disables header-based framing altogether.
        trust_forwarded (bool): ``True`` (default) if the RFC 7239
            ``Forwarded`` header is trusted. When ``False``,
            :attr:`~falcon.Request.forwarded` resolves to ``None`` and the
            ``'forwarded'`` entries of the other chains are skipped.
        scheme_headers (Sequence[str]): Header names consulted, in order of
            preference, when framing :attr:`~falcon.Request.forwarded_scheme`.
            Allowed values are ``'forwarded'`` and ``'x-forwarded-proto'``
            (default both, in that order).
        host_headers (Sequence[str]): Header names consulted, in order of
            preference, when framing :attr:`~falcon.Request.forwarded_host`.
            Allowed values are ``'forwarded'`` and ``'x-forwarded-host'``
            (default both, in that order).
        append_peer_address (bool): ``True`` (default) if the directly
            connected peer address (``REMOTE_ADDR`` under WSGI, or the ASGI
            ``client`` scope field) should be appended to
            :attr:`~falcon.Request.access_route` when it is not already the
            last hop, and used as the sole entry when no trusted header was
            found. Set to ``False`` to frame the route from headers only.
    """

    __slots__ = (
        'name',
        'access_route_headers',
        'trust_forwarded',
        'scheme_headers',
        'host_headers',
        'append_peer_address',
    )

    name: str | None
    """Human-readable label identifying the profile, or ``None``."""
    access_route_headers: tuple[str, ...]
    """Ordered lowercase header names used to frame the access route."""
    trust_forwarded: bool
    """Whether the RFC 7239 ``Forwarded`` header is trusted."""
    scheme_headers: tuple[str, ...]
    """Ordered lowercase header names used to frame the forwarded scheme."""
    host_headers: tuple[str, ...]
    """Ordered lowercase header names used to frame the forwarded host."""
    append_peer_address: bool
    """Whether the direct peer address is appended to the access route."""

    def __init__(
        self,
        *,
        name: str | None = None,
        access_route_headers: Sequence[str] = _DEFAULT_ACCESS_ROUTE_HEADERS,
        trust_forwarded: bool = True,
        scheme_headers: Sequence[str] = _DEFAULT_SCHEME_HEADERS,
        host_headers: Sequence[str] = _DEFAULT_HOST_HEADERS,
        append_peer_address: bool = True,
    ) -> None:
        self.name = name
        self.access_route_headers = _validate_headers(
            access_route_headers,
            _ACCESS_ROUTE_CHOICES,
            'TrustProfile.access_route_headers',
        )
        self.trust_forwarded = trust_forwarded
        self.scheme_headers = _validate_headers(
            scheme_headers, _SCHEME_CHOICES, 'TrustProfile.scheme_headers'
        )
        self.host_headers = _validate_headers(
            host_headers, _HOST_CHOICES, 'TrustProfile.host_headers'
        )
        self.append_peer_address = append_peer_address

    def __repr__(self) -> str:
        label = self.name or 'unlabeled'
        return f'<TrustProfile: {label}>'
