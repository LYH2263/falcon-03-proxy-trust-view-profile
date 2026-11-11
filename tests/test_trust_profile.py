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

"""Tests for the declarative :class:`falcon.TrustProfile`.

The acceptance scenarios are exercised on both WSGI and ASGI Requests that
share the ``req_options`` of a single :class:`falcon.asgi.App` instance
(which is also a :class:`falcon.App`), so that the two flavors can never
silently drift apart behind two unrelated applications.
"""

import pytest

import falcon
import falcon.testing

PEER = '10.0.0.7'

RICH_HEADERS = {
    'Forwarded': 'for=1.1.1.1;proto=https;host=public.example',
    'X-Forwarded-For': '9.9.9.9, 9.9.9.10',
    'X-Forwarded-Proto': 'http',
    'X-Forwarded-Host': 'classic.example',
    'X-Real-IP': '198.51.100.7',
}

MALFORMED_FORWARDED = 'invalid'


def _strict_profile():
    # A profile that distrusts the RFC 7239 Forwarded header and frames every
    # chain exclusively from the classic de-facto standard headers.
    return falcon.TrustProfile(
        name='strict-classic',
        access_route_headers=('x-forwarded-for', 'x-real-ip'),
        trust_forwarded=False,
        scheme_headers=('x-forwarded-proto',),
        host_headers=('x-forwarded-host',),
    )


def _snapshot(req):
    """Read all four proxy trust chains plus their composed products."""
    forwarded = req.forwarded
    return {
        'label': req.trust_profile,
        'access_route': list(req.access_route),
        'forwarded': None
        if forwarded is None
        else [(hop.src, hop.scheme, hop.host) for hop in forwarded],
        'forwarded_scheme': req.forwarded_scheme,
        'forwarded_host': req.forwarded_host,
        'forwarded_uri': req.forwarded_uri,
        'forwarded_prefix': req.forwarded_prefix,
        'remote_addr': req.remote_addr,
        'uri': req.uri,
    }


# ---------------------------------------------------------------------------
# TrustProfile declaration/validation
# ---------------------------------------------------------------------------


class TestTrustProfileDeclaration:
    def test_defaults_match_pin_headers(self):
        profile = falcon.TrustProfile()

        assert profile.name is None
        assert profile.access_route_headers == (
            'forwarded',
            'x-forwarded-for',
            'x-real-ip',
        )
        assert profile.trust_forwarded is True
        assert profile.scheme_headers == ('forwarded', 'x-forwarded-proto')
        assert profile.host_headers == ('forwarded', 'x-forwarded-host')
        assert profile.append_peer_address is True
        assert repr(profile) == '<TrustProfile: unlabeled>'

    def test_name_and_repr(self):
        profile = falcon.TrustProfile(name='edge-dc')
        assert profile.name == 'edge-dc'
        assert repr(profile) == '<TrustProfile: edge-dc>'

    def test_header_names_are_case_insensitive(self):
        profile = falcon.TrustProfile(
            access_route_headers=('X-Forwarded-For', 'X-Real-IP'),
            scheme_headers=('X-Forwarded-Proto',),
            host_headers=('X-Forwarded-Host',),
        )
        assert profile.access_route_headers == ('x-forwarded-for', 'x-real-ip')
        assert profile.scheme_headers == ('x-forwarded-proto',)
        assert profile.host_headers == ('x-forwarded-host',)

    @pytest.mark.parametrize(
        'kwargs,match',
        [
            (
                {'access_route_headers': ('x-forwarded-proto',)},
                'access_route_headers',
            ),
            ({'scheme_headers': ('x-real-ip',)}, 'scheme_headers'),
            ({'host_headers': ('x-forwarded-for',)}, 'host_headers'),
        ],
    )
    def test_unsupported_header_rejected(self, kwargs, match):
        with pytest.raises(ValueError, match=match):
            falcon.TrustProfile(**kwargs)

    def test_duplicate_header_rejected(self):
        with pytest.raises(ValueError, match='must not list the same header'):
            falcon.TrustProfile(
                access_route_headers=('x-forwarded-for', 'X-Forwarded-For')
            )

    def test_empty_sequences_allowed(self):
        profile = falcon.TrustProfile(
            access_route_headers=(),
            scheme_headers=(),
            host_headers=(),
            append_peer_address=False,
        )
        assert profile.access_route_headers == ()
        assert profile.scheme_headers == ()
        assert profile.host_headers == ()
        assert profile.append_peer_address is False

    def test_request_options_default_is_none(self):
        options = falcon.RequestOptions()
        assert options.trust_profile is None

        req = falcon.testing.create_req()
        assert req.trust_profile is None
        assert req.options.trust_profile is None


# ---------------------------------------------------------------------------
# Per-chain behavior, parametrized over both WSGI and ASGI flavors
# ---------------------------------------------------------------------------


@pytest.fixture()
def profile_options():
    def _factory(profile):
        options = falcon.RequestOptions()
        options.trust_profile = profile
        return options

    return _factory


class TestProfileChains:
    def test_default_profile_equivalent_to_pin(self, util, asgi):
        pin_req = util.create_req(asgi, headers=RICH_HEADERS, remote_addr=PEER)

        options = falcon.RequestOptions()
        options.trust_profile = falcon.TrustProfile()
        profiled_req = util.create_req(
            asgi, options=options, headers=RICH_HEADERS, remote_addr=PEER
        )

        pin_snapshot = _snapshot(pin_req)
        profiled_snapshot = _snapshot(profiled_req)
        pin_snapshot.pop('label')
        profiled_snapshot.pop('label')
        assert profiled_snapshot == pin_snapshot

        assert profiled_req.trust_profile is not None
        assert pin_req.trust_profile is None

    def test_forwarded_and_xff_coexist_access_route_prefers_forwarded(self, util, asgi):
        # Pin behavior: the first *present* header wins, without falling
        # through on parse quirks.
        req = util.create_req(asgi, headers=RICH_HEADERS, remote_addr=PEER)
        assert req.access_route == ['1.1.1.1', PEER]

    def test_profile_can_reorder_access_route_headers(self, util, asgi):
        profile = falcon.TrustProfile(
            access_route_headers=('x-forwarded-for', 'forwarded')
        )
        options = falcon.RequestOptions()
        options.trust_profile = profile
        req = util.create_req(
            asgi, options=options, headers=RICH_HEADERS, remote_addr=PEER
        )

        assert req.trust_profile is profile
        assert req.access_route == ['9.9.9.9', '9.9.9.10', PEER]

    def test_distrust_forwarded_disables_all_forwarded_chain_views(self, util, asgi):
        options = falcon.RequestOptions()
        options.trust_profile = _strict_profile()
        req = util.create_req(
            asgi, options=options, headers=RICH_HEADERS, remote_addr=PEER
        )

        # Chain 2: the Forwarded header is framed as absent.
        assert req.forwarded is None

        # Chain 1: falls through to X-Forwarded-For instead of Forwarded.
        assert req.access_route == ['9.9.9.9', '9.9.9.10', PEER]

        # Chain 3: classic headers win even though Forwarded is present.
        assert req.forwarded_scheme == 'http'
        assert req.forwarded_host == 'classic.example'

        # Chain 4: recombined from the classic chain values.
        assert req.forwarded_uri == 'http://classic.example/'
        assert req.forwarded_prefix == 'http://classic.example'

    def test_distrust_forwarded_with_only_forwarded_present(self, util, asgi):
        options = falcon.RequestOptions()
        options.trust_profile = _strict_profile()
        req = util.create_req(
            asgi,
            options=options,
            headers={'Forwarded': RICH_HEADERS['Forwarded']},
            remote_addr=PEER,
        )

        assert req.forwarded is None
        assert req.access_route == [PEER]
        assert req.forwarded_scheme == 'http'
        assert req.forwarded_host == 'falconframework.org'

    def test_malformed_forwarded_does_not_fall_through(self, util, asgi):
        headers = {
            'Forwarded': MALFORMED_FORWARDED,
            'X-Forwarded-For': '9.9.9.9',
            'X-Forwarded-Proto': 'https',
            'X-Forwarded-Host': 'classic.example',
        }

        pin_req = util.create_req(asgi, headers=headers, remote_addr=PEER)
        # Forwarded is present but yields no hops; the route keeps that
        # framing instead of silently switching to X-Forwarded-For.
        assert pin_req.forwarded == []
        assert pin_req.access_route == [PEER]
        assert pin_req.forwarded_scheme == 'http'
        assert pin_req.forwarded_host == 'falconframework.org'

        options = falcon.RequestOptions()
        options.trust_profile = falcon.TrustProfile()
        profiled_req = util.create_req(
            asgi, options=options, headers=headers, remote_addr=PEER
        )
        assert profiled_req.forwarded == []
        assert profiled_req.access_route == [PEER]

    def test_distrust_forwarded_with_default_header_order_skips_forwarded(
        self, util, asgi
    ):
        # The default header sequences still list Forwarded first; with
        # trust disabled it must be skipped in favor of the next header on
        # every chain (loop back-edge / continue coverage).
        profile = falcon.TrustProfile(
            name='distrust-default-order', trust_forwarded=False
        )
        options = falcon.RequestOptions()
        options.trust_profile = profile
        req = util.create_req(
            asgi, options=options, headers=RICH_HEADERS, remote_addr=PEER
        )

        assert req.trust_profile is profile
        assert req.forwarded is None
        assert req.access_route == ['9.9.9.9', '9.9.9.10', PEER]
        assert req.forwarded_scheme == 'http'
        assert req.forwarded_host == 'classic.example'
        assert req.forwarded_uri == 'http://classic.example/'

    def test_profile_skips_absent_forwarded_then_matches_xff(self, util, asgi):
        profile = falcon.TrustProfile()
        options = falcon.RequestOptions()
        options.trust_profile = profile
        req = util.create_req(
            asgi,
            options=options,
            headers={'X-Forwarded-For': '9.9.9.9'},
            remote_addr=PEER,
        )

        assert req.access_route == ['9.9.9.9', PEER]
        assert req.forwarded is None
        assert req.forwarded_scheme == 'http'
        assert req.forwarded_host == 'falconframework.org'

    def test_malformed_forwarded_under_profile_scheme_host_fallbacks(self, util, asgi):
        profile = falcon.TrustProfile()
        options = falcon.RequestOptions()
        options.trust_profile = profile
        req = util.create_req(
            asgi,
            options=options,
            headers={
                'Forwarded': MALFORMED_FORWARDED,
                'X-Forwarded-Proto': 'https',
                'X-Forwarded-Host': 'classic.example',
            },
            remote_addr=PEER,
        )

        assert req.forwarded == []
        assert req.access_route == [PEER]
        # Forwarded is present but unparseable, so the first-hop fallback is
        # the Request's own scheme/host rather than the classic headers.
        assert req.forwarded_scheme == 'http'
        assert req.forwarded_host == 'falconframework.org'
        assert req.forwarded_uri == 'http://falconframework.org/'

    def test_only_x_forwarded_host_forks_forwarded_uri(self, util, asgi):
        req = util.create_req(
            asgi,
            headers={'X-Forwarded-Host': 'alb.example'},
            remote_addr=PEER,
        )

        assert req.uri == 'http://falconframework.org/'
        assert req.forwarded_uri == 'http://alb.example/'
        assert req.forwarded_prefix == 'http://alb.example'
        assert req.forwarded_host == 'alb.example'
        assert req.forwarded_scheme == 'http'

    def test_only_x_forwarded_proto_forks_scheme(self, util, asgi):
        req = util.create_req(
            asgi,
            headers={'X-Forwarded-Proto': 'https'},
            remote_addr=PEER,
        )
        assert req.scheme == 'http'
        assert req.forwarded_scheme == 'https'
        assert req.forwarded_uri == 'https://falconframework.org/'

    def test_empty_scheme_and_host_header_sequences_fall_back_to_self(self, util, asgi):
        profile = falcon.TrustProfile(scheme_headers=(), host_headers=())
        options = falcon.RequestOptions()
        options.trust_profile = profile
        req = util.create_req(
            asgi, options=options, headers=RICH_HEADERS, remote_addr=PEER
        )

        assert req.forwarded_scheme == 'http'
        assert req.forwarded_host == 'falconframework.org'
        assert req.forwarded_uri == 'http://falconframework.org/'

    def test_no_headers_empty_access_route_headers_peer_only(self, util, asgi):
        profile = falcon.TrustProfile(access_route_headers=())
        options = falcon.RequestOptions()
        options.trust_profile = profile
        req = util.create_req(asgi, options=options, remote_addr=PEER)

        assert req.access_route == [PEER]

    def test_append_peer_address_disabled_keeps_headers_only(self, util, asgi):
        profile = falcon.TrustProfile(append_peer_address=False)
        options = falcon.RequestOptions()
        options.trust_profile = profile
        req = util.create_req(
            asgi, options=options, headers=RICH_HEADERS, remote_addr=PEER
        )

        assert req.access_route == ['1.1.1.1']

        bare = util.create_req(
            asgi,
            options=options,
            remote_addr=PEER,
        )
        assert bare.access_route == []

    def test_duplicate_peer_hop_is_not_appended_twice(self, util, asgi):
        profile = falcon.TrustProfile(access_route_headers=('x-forwarded-for',))
        options = falcon.RequestOptions()
        options.trust_profile = profile
        req = util.create_req(
            asgi,
            options=options,
            headers={'X-Forwarded-For': f'9.9.9.9, {PEER}'},
            remote_addr=PEER,
        )
        assert req.access_route == ['9.9.9.9', PEER]

    def test_multi_hop_forwarded_frames_every_hop(self, util, asgi):
        profile = falcon.TrustProfile()
        options = falcon.RequestOptions()
        options.trust_profile = profile
        headers = {
            'Forwarded': ('for=1.1.1.1, for=1.1.1.2;proto=https;host=public.example'),
            'X-Forwarded-For': '9.9.9.9',
        }
        req = util.create_req(asgi, options=options, headers=headers, remote_addr=PEER)

        # Forwarded wins over X-Forwarded-For and preserves every hop.
        assert req.access_route == ['1.1.1.1', '1.1.1.2', PEER]
        assert [hop.src for hop in req.forwarded] == [
            '1.1.1.1',
            '1.1.1.2',
        ]

    def test_forwarded_hop_without_for_is_skipped_in_route(self, util, asgi):
        profile = falcon.TrustProfile()
        options = falcon.RequestOptions()
        options.trust_profile = profile
        req = util.create_req(
            asgi,
            options=options,
            headers={'Forwarded': ('for=1.1.1.1, proto=https;host=public.example')},
            remote_addr=PEER,
        )

        assert len(req.forwarded) == 2
        assert req.forwarded[1].src is None
        assert req.access_route == ['1.1.1.1', PEER]

    def test_x_real_ip_chain(self, util, asgi):
        profile = falcon.TrustProfile(access_route_headers=('x-real-ip',))
        options = falcon.RequestOptions()
        options.trust_profile = profile
        req = util.create_req(
            asgi,
            options=options,
            headers={'X-Real-IP': '198.51.100.7'},
            remote_addr=PEER,
        )
        assert req.access_route == ['198.51.100.7', PEER]

    def test_forwarded_prefix_uses_root_path(self, util, asgi):
        options = falcon.RequestOptions()
        options.trust_profile = _strict_profile()
        req = util.create_req(
            asgi,
            options=options,
            path='/reports/daily',
            root_path='/gw',
            headers=RICH_HEADERS,
            remote_addr=PEER,
        )
        assert req.forwarded_prefix == 'http://classic.example/gw'
        assert req.forwarded_uri == ('http://classic.example/gw/reports/daily')


# ---------------------------------------------------------------------------
# Cache independence and per-Request freezing
# ---------------------------------------------------------------------------


class TestCachingAndFreezing:
    def test_read_order_does_not_change_observable_values(self, util, asgi):
        options = falcon.RequestOptions()
        options.trust_profile = _strict_profile()

        req_uri_first = util.create_req(
            asgi, options=options, headers=RICH_HEADERS, remote_addr=PEER
        )
        req_route_first = util.create_req(
            asgi, options=options, headers=RICH_HEADERS, remote_addr=PEER
        )

        _ = req_uri_first.forwarded_uri
        _ = req_uri_first.access_route

        _ = req_route_first.access_route
        _ = req_route_first.forwarded_uri

        assert _snapshot(req_uri_first) == _snapshot(req_route_first)

    def test_four_caches_are_independent_and_frozen_on_same_instance(self, util, asgi):
        options = falcon.RequestOptions()
        profile = _strict_profile()
        options.trust_profile = profile
        req = util.create_req(
            asgi, options=options, headers=RICH_HEADERS, remote_addr=PEER
        )

        # Warm the four cached chains.
        cached_before = {
            'label': req.trust_profile,
            'access_route': list(req.access_route),
            'forwarded': req.forwarded,
            'forwarded_uri': req.forwarded_uri,
            'forwarded_prefix': req.forwarded_prefix,
        }

        # Corrupt the underlying transport representation after the four
        # caches have been written. The cached chains must not recompute.
        if asgi:
            req._asgi_headers.clear()
            req.scope['headers'] = []
        else:
            for key in (
                'HTTP_FORWARDED',
                'HTTP_X_FORWARDED_FOR',
                'HTTP_X_FORWARDED_PROTO',
                'HTTP_X_FORWARDED_HOST',
                'HTTP_X_REAL_IP',
            ):
                req.env.pop(key, None)

        assert req.trust_profile is profile
        assert list(req.access_route) == cached_before['access_route']
        assert req.forwarded is cached_before['forwarded']
        assert req.forwarded_uri == cached_before['forwarded_uri']
        assert req.forwarded_prefix == cached_before['forwarded_prefix']

        # Advancing the host profile afterwards must not write through the
        # frozen Request either.
        options.trust_profile = falcon.TrustProfile(name='after')
        assert req.trust_profile is profile
        assert list(req.access_route) == cached_before['access_route']
        assert req.forwarded_uri == cached_before['forwarded_uri']
        assert req.forwarded_prefix == cached_before['forwarded_prefix']

    def test_snapshot_freezes_uncached_chains_against_profile_advancement(
        self, util, asgi
    ):
        options = falcon.RequestOptions()
        profile = _strict_profile()
        options.trust_profile = profile
        req = util.create_req(
            asgi, options=options, headers=RICH_HEADERS, remote_addr=PEER
        )

        before = _snapshot(req)

        # NOTE: forwarded_scheme/forwarded_host are intentionally uncached
        #   live views; advancing the profile must not change them because
        #   the Request keeps its construction-time profile snapshot.
        options.trust_profile = falcon.TrustProfile(name='after')

        assert _snapshot(req) == before
        assert req.trust_profile is profile

    def test_uncached_chains_still_follow_snapshot_after_advancement(self, util, asgi):
        options = falcon.RequestOptions()
        strict = _strict_profile()
        options.trust_profile = strict

        req = util.create_req(
            asgi, options=options, headers=RICH_HEADERS, remote_addr=PEER
        )

        # Warm only one of the four chains.
        assert req.access_route == ['9.9.9.9', '9.9.9.10', PEER]

        # Advance the profile before the other chains are ever read.
        options.trust_profile = falcon.TrustProfile(name='pin-like')

        assert req.trust_profile is strict
        assert req.forwarded is None
        assert req.forwarded_scheme == 'http'
        assert req.forwarded_host == 'classic.example'
        assert req.forwarded_uri == 'http://classic.example/'

    def test_new_request_uses_advanced_profile_on_all_chains(self, util, asgi):
        options = falcon.RequestOptions()
        options.trust_profile = falcon.TrustProfile(name='pin-like')
        old_req = util.create_req(
            asgi, options=options, headers=RICH_HEADERS, remote_addr=PEER
        )
        assert old_req.access_route == ['1.1.1.1', PEER]
        assert old_req.forwarded_scheme == 'https'

        strict = _strict_profile()
        options.trust_profile = strict
        new_req = util.create_req(
            asgi, options=options, headers=RICH_HEADERS, remote_addr=PEER
        )

        assert old_req.trust_profile.name == 'pin-like'
        assert new_req.trust_profile is strict
        assert new_req.access_route == ['9.9.9.9', '9.9.9.10', PEER]
        assert new_req.forwarded is None
        assert new_req.forwarded_scheme == 'http'
        assert new_req.forwarded_host == 'classic.example'
        assert new_req.forwarded_uri == 'http://classic.example/'


# ---------------------------------------------------------------------------
# Same-App WSGI + ASGI acceptance (single App instance, shared req_options)
# ---------------------------------------------------------------------------


class TestSameAppWsgiAsgiAcceptance:
    def setup_method(self):
        # falcon.asgi.App is a subclass of falcon.app.App, so this single
        # instance carries one req_options consumed by both flavors.
        self.app = falcon.asgi.App()
        assert isinstance(self.app, falcon.App)
        self.options = self.app.req_options

    def _pair(self, **kwargs):
        wsgi_req = falcon.testing.create_req(options=self.options, **kwargs)
        asgi_req = falcon.testing.create_asgi_req(options=self.options, **kwargs)

        # Both Requests must be framed by the very same host options object.
        assert wsgi_req.options is self.app.req_options
        assert asgi_req.options is self.app.req_options
        return wsgi_req, asgi_req

    def test_forwarded_and_xff_coexist_only_forwarded_is_framed(self):
        wsgi_req, asgi_req = self._pair(headers=RICH_HEADERS, remote_addr=PEER)
        for req in (wsgi_req, asgi_req):
            assert req.access_route == ['1.1.1.1', PEER]
            assert req.forwarded[0].src == '1.1.1.1'

    def test_only_x_forwarded_host_forks_uri(self):
        wsgi_req, asgi_req = self._pair(
            headers={'X-Forwarded-Host': 'alb.example'}, remote_addr=PEER
        )
        for req in (wsgi_req, asgi_req):
            assert req.uri == 'http://falconframework.org/'
            assert req.forwarded_uri == 'http://alb.example/'
            assert req.forwarded_prefix == 'http://alb.example'

    def test_malformed_forwarded_list_behavior(self):
        wsgi_req, asgi_req = self._pair(
            headers={
                'Forwarded': MALFORMED_FORWARDED,
                'X-Forwarded-For': '9.9.9.9',
            },
            remote_addr=PEER,
        )
        for req in (wsgi_req, asgi_req):
            assert req.forwarded == []
            assert req.access_route == [PEER]
            assert req.forwarded_scheme == 'http'
            assert req.forwarded_host == 'falconframework.org'

    def test_profile_advancement_forks_old_and_new_requests(self):
        self.options.trust_profile = falcon.TrustProfile(name='pin-like')
        old_wsgi, old_asgi = self._pair(headers=RICH_HEADERS, remote_addr=PEER)

        # Warm every chain on the old Requests.
        old_wsgi_snapshot = _snapshot(old_wsgi)
        old_asgi_snapshot = _snapshot(old_asgi)

        strict = _strict_profile()
        self.options.trust_profile = strict

        new_wsgi, new_asgi = self._pair(headers=RICH_HEADERS, remote_addr=PEER)

        # Old Requests keep both the label and the four return values.
        assert old_wsgi.trust_profile.name == 'pin-like'
        assert old_asgi.trust_profile.name == 'pin-like'
        assert _snapshot(old_wsgi) == old_wsgi_snapshot
        assert _snapshot(old_asgi) == old_asgi_snapshot

        # New Requests follow the advanced profile on all four chains.
        for req in (new_wsgi, new_asgi):
            assert req.trust_profile is strict
            assert req.access_route == ['9.9.9.9', '9.9.9.10', PEER]
            assert req.forwarded is None
            assert req.forwarded_scheme == 'http'
            assert req.forwarded_host == 'classic.example'
            assert req.forwarded_uri == 'http://classic.example/'

    def test_wsgi_remote_addr_diverges_from_access_route_tail(self):
        # WSGI reads REMOTE_ADDR directly; with peer appending disabled the
        # access route tail no longer coincides with remote_addr.
        self.options.trust_profile = falcon.TrustProfile(
            name='headers-only', append_peer_address=False
        )
        wsgi_req, asgi_req = self._pair(
            headers={'X-Real-IP': '203.0.113.5'}, remote_addr=PEER
        )

        assert wsgi_req.access_route == ['203.0.113.5']
        assert wsgi_req.remote_addr == PEER

        # ASGI semantics differ: remote_addr is defined as the last hop.
        assert asgi_req.access_route == ['203.0.113.5']
        assert asgi_req.remote_addr == '203.0.113.5'

    def test_asgi_remote_addr_equals_last_access_route_hop(self):
        self.options.trust_profile = _strict_profile()
        wsgi_req, asgi_req = self._pair(headers=RICH_HEADERS, remote_addr=PEER)

        assert asgi_req.access_route == ['9.9.9.9', '9.9.9.10', PEER]
        assert asgi_req.remote_addr == asgi_req.access_route[-1] == PEER

        # WSGI happens to end on the same peer here, but via a direct read.
        assert wsgi_req.remote_addr == PEER
        assert wsgi_req.access_route[-1] == PEER

    def test_missing_peer_defaults_consistently(self):
        wsgi_req, asgi_req = self._pair(headers=RICH_HEADERS)
        assert wsgi_req.remote_addr == '127.0.0.1'
        assert asgi_req.remote_addr == '127.0.0.1'
        assert wsgi_req.access_route[-1] == '127.0.0.1'
        assert asgi_req.access_route[-1] == '127.0.0.1'


# ---------------------------------------------------------------------------
# End-to-end: a real ASGI App constructs Requests under the advanced profile
# ---------------------------------------------------------------------------


class _EchoResource:
    async def on_get(self, req, resp):
        forwarded = req.forwarded
        resp.media = {
            'label': req.trust_profile.name if req.trust_profile else None,
            'access_route': req.access_route,
            'forwarded': None
            if forwarded is None
            else [(hop.src, hop.scheme, hop.host) for hop in forwarded],
            'forwarded_scheme': req.forwarded_scheme,
            'forwarded_host': req.forwarded_host,
            'forwarded_uri': req.forwarded_uri,
            'forwarded_prefix': req.forwarded_prefix,
            'remote_addr': req.remote_addr,
        }


class TestAppEndToEnd:
    def setup_method(self):
        self.app = falcon.asgi.App()
        self.app.add_route('/echo', _EchoResource())
        self.client = falcon.testing.TestClient(self.app)

    def test_profile_advancement_is_observed_by_app_constructed_requests(self):
        before = self.client.simulate_get(
            '/echo', headers=RICH_HEADERS, remote_addr=PEER
        )
        assert before.json['label'] is None
        assert before.json['access_route'] == ['1.1.1.1', PEER]
        assert before.json['forwarded_scheme'] == 'https'
        assert before.json['forwarded_host'] == 'public.example'
        assert before.json['forwarded_uri'] == ('https://public.example/echo')

        self.app.req_options.trust_profile = _strict_profile()

        after = self.client.simulate_get(
            '/echo', headers=RICH_HEADERS, remote_addr=PEER
        )
        assert after.json['label'] == 'strict-classic'
        assert after.json['access_route'] == [
            '9.9.9.9',
            '9.9.9.10',
            PEER,
        ]
        assert after.json['forwarded'] is None
        assert after.json['forwarded_scheme'] == 'http'
        assert after.json['forwarded_host'] == 'classic.example'
        assert after.json['forwarded_uri'] == ('http://classic.example/echo')
        assert after.json['forwarded_prefix'] == 'http://classic.example'
        assert after.json['remote_addr'] == PEER
