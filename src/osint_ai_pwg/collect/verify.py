"""Verify observation proof URLs before they reach the graph.

The collectors are existence checkers, so a hit is only as good as the URL behind it.
Two kinds of noise get dropped here:

* dead links - HTTP 4xx/5xx, DNS failures, timeouts
* root-only URLs - ``https://site/`` proves the site is up, not that the handle exists
"""

from __future__ import annotations

import concurrent.futures
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlparse

from osint_ai_pwg.schemas import Observation

_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)


@dataclass(frozen=True)
class LinkCheck:
    url: str
    ok: bool
    status: int | None
    reason: str


def _root_only(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return True
    return parsed.path in ("", "/") and not parsed.query


def check_link(url: str, timeout: float = 6.0) -> LinkCheck:
    """HEAD the proof URL, fall back to GET when a site rejects HEAD."""
    if not url:
        return LinkCheck(url, False, None, "no-url")
    if _root_only(url):
        return LinkCheck(url, False, None, "root-only")

    headers = {
        "User-Agent": _UA,
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    }
    for method in ("HEAD", "GET"):
        try:
            req = urllib.request.Request(url, method=method, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = int(getattr(resp, "status", 200))
                if 200 <= status < 400:
                    return LinkCheck(url, True, status, "ok")
                return LinkCheck(url, False, status, f"http-{status}")
        except urllib.error.HTTPError as exc:
            if method == "HEAD" and exc.code in (403, 405, 501):
                continue
            return LinkCheck(url, False, exc.code, f"http-{exc.code}")
        except Exception as exc:  # DNS, TLS, timeout, malformed URL
            return LinkCheck(url, False, None, type(exc).__name__)
    return LinkCheck(url, False, None, "unreachable")


def verify_observations(
    observations: list[Observation],
    *,
    timeout: float = 6.0,
    workers: int = 12,
) -> tuple[list[Observation], list[tuple[Observation, LinkCheck]], dict[str, LinkCheck]]:
    """Return (kept, dropped, checks). One HTTP call per distinct URL."""
    urls = sorted({o.url for o in observations if o.url})
    checks: dict[str, LinkCheck] = {}
    if urls:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            for check in pool.map(lambda u: check_link(u, timeout=timeout), urls):
                checks[check.url] = check

    kept: list[Observation] = []
    dropped: list[tuple[Observation, LinkCheck]] = []
    for obs in observations:
        if not obs.url:
            kept.append(obs)  # no link to disprove; email/breach hits stay
            continue
        check = checks[obs.url]
        if check.ok:
            kept.append(obs)
        else:
            dropped.append((obs, check))
    return kept, dropped, checks
