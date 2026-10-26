"""Test-suite guarantees that hold for every test.

The one that matters: no test may reach the network.

``pob.feeds`` is the only module that opens a socket, and every published
number in this repository comes from the simulated corpus rather than from it.
A test that reached the live EPSS or KEV feed would depend on those services
being up and on the runner having outbound access. The sandbox this repository
was built in has none, so such a test passes there and then behaves differently
on a CI runner that does have egress.

That is not hypothetical: ``test_fetch_reports_the_feed_error_rather_than_a_traceback``
asserted that ``pob fetch`` exits 2 because the feed could not be reached. That
was true only because the build sandbox blocked egress. On a GitHub runner the
real feeds are reachable, ``fetch`` succeeds, and the assertion flipped from 2
to 0.

Blocking the network here fixes that for the whole suite at once rather than one
test at a time, and makes the fetch error path deterministic everywhere. The
textual guard in CI ("no test reaches the live feeds") stays as a second line of
defence; this fixture is the one that actually enforces it at runtime.
"""

from __future__ import annotations

import urllib.error
import urllib.request

import pytest


@pytest.fixture(autouse=True)
def block_outbound_network(monkeypatch):
    """Make any real outbound request fail loudly, in every test.

    ``pob.feeds.fetch`` looks up ``urllib.request.urlopen`` at call time, so
    replacing the attribute on the module reaches it. A test that wants to
    exercise a successful fetch must stub the parser inputs rather than reach a
    live host, and a test that exercises the failure path gets a deterministic
    failure instead of relying on the environment to provide one.
    """

    def refuse(*args, **kwargs):
        raise urllib.error.URLError(
            "outbound network is blocked in the test suite (tests must not reach the live feeds)"
        )

    monkeypatch.setattr(urllib.request, "urlopen", refuse)
