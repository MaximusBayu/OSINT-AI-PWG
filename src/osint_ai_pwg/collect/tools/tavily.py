"""Tavily discovery: search the open web for a target's PII.

The verifiers (sherlock, holehe, maigret, ...) confirm a KNOWN handle on a fixed site
list. Tavily is the inverse: it DISCOVERS new PII and identifiers from public web search.
Every observation it emits is tagged `INFERRED` (low confidence) because a search hit is
weak evidence and can be a different person. Two guardrails keep wrong anchors from
becoming confident garbage:

1. Provenance — Tavily never emits `STATED`. It is always `INFERRED` (directness 0.2).
2. Consistency gate — a search result is only mined if it actually references the target
   (a distinctive seed token: surname / full name / username / email), which drops the
   "different person with the same first name" false positive.

Source URLs are kept so the UI can render the proof link for every discovered fact.
"""

from __future__ import annotations

import os
import re

from osint_ai_pwg.collect.base import Collector
from osint_ai_pwg.schemas import Directness, FieldGroup, Observation

name = "tavily"

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE = re.compile(r"\+?\d[\d ()\-]{7,}\d")
_BIRTH = re.compile(r"(?:born|birth(?:day|date)?|b\.)\D{0,16}((?:19|20)\d{2})", re.IGNORECASE)
# profile-URL patterns -> a username/handle worth feeding to the verifiers later.
_HANDLE_HOSTS = (
    ("github.com", r"github\.com/([A-Za-z0-9_-]{3,})"),
    ("x.com", r"(?:x|twitter)\.com/([A-Za-z0-9_]{3,})"),
    ("reddit.com", r"reddit\.com/(?:u|user)/([A-Za-z0-9_-]{3,})"),
    ("instagram.com", r"instagram\.com/([A-Za-z0-9._]{3,})"),
    ("linkedin.com", r"linkedin\.com/in/([A-Za-z0-9._%-]{3,})"),
    ("tiktok.com", r"tiktok\.com/@([A-Za-z0-9._]{3,})"),
    ("steamcommunity.com", r"steamcommunity\.com/(?:id|profiles)/([A-Za-z0-9_-]{3,})"),
    ("gitlab.com", r"gitlab\.com/([A-Za-z0-9._-]{3,})"),
)
_JUNK_EMAIL_SUFFIX = ("example.com", "domain.com", "yourdomain.com", "email.com")

_MONTH_NAMES = (
    "January", "February", "March", "April", "May", "June", "July", "August",
    "September", "October", "November", "December", "Jan", "Feb", "Mar", "Apr",
    "Jun", "Jul", "Aug", "Sep", "Sept", "Oct", "Nov", "Dec",
)
_MONTH_ALT = "|".join(_MONTH_NAMES)
_BIRTH_MONTH = re.compile(r"(?:born|birth(?:day|date)?|dob)\D{0,24}(" + _MONTH_ALT + r")\b", re.IGNORECASE)
_BIRTH_DAY = re.compile(r"(?:born|birth(?:day|date)?|dob)\D{0,24}(?:" + _MONTH_ALT + r")\b[.\s,]{0,4}(\d{1,2})(?!\d)", re.IGNORECASE)

# Best-effort gazetteers (curated, not exhaustive). City/country can only be pulled
# from a snippet by matching against a known name list.
_CITY_NAMES = (
    "jakarta", "bandung", "surabaya", "medan", "semarang", "yogyakarta", "makassar",
    "palembang", "depok", "tangerang", "bekasi", "bogor", "malang", "padang", "denpasar",
    "balikpapan", "banjarmasin", "surakarta", "solo", "pekanbaru", "samarinda",
    "tasikmalaya", "cirebon", "pontianak", "manado", "batam", "ambon", "kupang",
    "mataram", "jambi", "bengkulu", "serang", "new york", "los angeles", "san francisco",
    "chicago", "london", "paris", "berlin", "tokyo", "singapore", "kuala lumpur",
    "sydney", "melbourne", "amsterdam", "dubai", "seoul", "bangkok", "hong kong",
    "toronto", "vancouver", "moscow", "mumbai", "delhi", "beijing", "shanghai",
    "taipei", "manila", "brisbane", "perth", "auckland",
)
_COUNTRY_NAMES = (
    "indonesia", "malaysia", "singapore", "united states", "australia", "united kingdom",
    "england", "canada", "germany", "france", "netherlands", "japan", "china", "india",
    "south korea", "thailand", "vietnam", "philippines", "brazil", "russia", "italy",
    "spain", "switzerland", "sweden", "norway", "denmark", "finland", "ireland",
    "new zealand", "saudi arabia", "united arab emirates", "qatar",
)
_CITY_RE = re.compile(r"\b(" + "|".join(re.escape(c) for c in _CITY_NAMES) + r")\b", re.IGNORECASE)
_COUNTRY_RE = re.compile(r"\b(" + "|".join(re.escape(c) for c in _COUNTRY_NAMES) + r")\b", re.IGNORECASE)
_ADDRESS = re.compile(r"\b(?:address|alamat)\b[:\s]{0,4}([A-Za-z0-9][^|;\n]{6,60})", re.IGNORECASE)


def _distinctive_tokens(name: str) -> set[str]:
    """The surname token (last word) — the identity gate for name matching.

    Dropping only the given name leaves common middle names (e.g. 'Bayu') that match
    unrelated hits (a company called 'Bayu Buana'). The last token is the distinctive
    part of a full name.
    """
    parts = [p for p in name.split() if p]
    if not parts:
        return set()
    return {parts[-1].lower()}


def _looks_like_phone(s: str) -> bool:
    """Reject the junk the phone regex drags in: dates and numeric coordinates."""
    if "\n" in s:
        return False
    if re.search(r"\d{4}\s?[-/]\s?\d{1,2}\s?[-/]\s?\d{1,2}", s):  # a date
        return False
    digits = re.sub(r"\D", "", s)
    return 9 <= len(digits) <= 15


class TavilyCollector(Collector):
    name = "tavily"

    def __init__(self, api_key: str | None = None, client=None,
                 max_results: int = 5, max_queries: int = 6) -> None:
        self.api_key = api_key if api_key is not None else os.environ.get("TAVILY_API_KEY", "")
        self._client = client          # injectable for tests (no live API)
        self.max_results = max_results
        self.max_queries = max_queries

    # -- plumbing -----------------------------------------------------------
    def _get_client(self):
        if self._client is not None:
            return self._client
        if not self.api_key:
            return None
        try:
            from tavily import TavilyClient
        except Exception:
            return None
        return TavilyClient(api_key=self.api_key)

    def _queries(self, seed: dict[str, str]) -> list[str]:
        name = (seed.get("name") or "").strip()
        username = (seed.get("username") or "").strip()
        email = (seed.get("email") or "").strip()
        qs: list[str] = []
        if name:
            qs.append(name)
            qs.append(f"{name} born OR birthday OR birthdate")
            qs.append(f"{name} phone OR contact")
        if username:
            qs.append(username)
        if email:
            qs.append(email)
        return qs[: self.max_queries]

    def _about_target(self, text: str, seed: dict[str, str]) -> bool:
        """Consistency gate: does this result actually reference the target?"""
        name = (seed.get("name") or "").strip()
        username = (seed.get("username") or "").strip()
        email = (seed.get("email") or "").strip()
        low = text.lower()
        for tok in _distinctive_tokens(name):
            if tok and tok in low:
                return True
        if username and username.lower() in low:
            return True
        if email and email.lower() in low:
            return True
        # no seed at all -> nothing to gate on, let it through
        return not (name or username or email)

    # -- extraction ---------------------------------------------------------
    def _extract(self, target_id: str, seed: dict[str, str], res: dict) -> list[Observation]:
        title = res.get("title") or ""
        content = res.get("content") or ""
        url = res.get("url") or ""
        text = f"{title}\n{content}\n{url}"
        if not self._about_target(text, seed):
            return []

        host = url.split("/")[2] if url.count("/") >= 3 else "web"
        src = f"tavily:{host.lower()}"
        seed_username = (seed.get("username") or "").lower()
        seed_email = (seed.get("email") or "").lower()

        obs: list[Observation] = []

        # discovered emails (new, plausible)
        for e in set(_EMAIL.findall(text)):
            el = e.lower()
            if el == seed_email:
                continue
            if el.endswith(_JUNK_EMAIL_SUFFIX) or el.startswith(("test", "user", "you@", "your")):
                continue
            obs.append(self._o(target_id, "email", FieldGroup.IDENTITY, e, src, url))

        # phone numbers (strictly gated — dates and coordinates are not phones)
        for p in set(_PHONE.findall(text)):
            if not _looks_like_phone(p):
                continue
            obs.append(self._o(target_id, "phone", FieldGroup.CONTACT, p.strip(), src, url))

        # birth year (heuristic; stays inferred)
        for y in set(_BIRTH.findall(text)):
            obs.append(self._o(target_id, "birth_year", FieldGroup.TEMPORAL, y, src, url))

        # username from a known profile URL
        for _host, pat in _HANDLE_HOSTS:
            m = re.search(pat, url, re.IGNORECASE)
            if m:
                handle = m.group(1).rstrip(".")
                if handle.lower() != seed_username:
                    obs.append(self._o(target_id, "username", FieldGroup.IDENTITY, handle, src, url))

        # birth month / day (from a born/birthday context)
        for m in set(_BIRTH_MONTH.findall(text)):
            obs.append(self._o(target_id, "birth_month", FieldGroup.TEMPORAL, m.capitalize(), src, url))
        for d in set(_BIRTH_DAY.findall(text)):
            if 1 <= int(d) <= 31:
                obs.append(self._o(target_id, "birth_day", FieldGroup.TEMPORAL, d, src, url))

        # city / country (gazetteer match)
        for city in set(_CITY_RE.findall(text)):
            obs.append(self._o(target_id, "city", FieldGroup.LOCATION, city.title(), src, url))
        for country in set(_COUNTRY_RE.findall(text)):
            obs.append(self._o(target_id, "country", FieldGroup.LOCATION, country.title(), src, url))

        # address (rare in snippets; conservative "address/alamat" context)
        for a in set(_ADDRESS.findall(text)):
            obs.append(self._o(target_id, "address", FieldGroup.LOCATION, a.strip(), src, url))

        return obs

    @staticmethod
    def _o(target_id: str, field: str, group: FieldGroup, value: str, source: str, url: str) -> Observation:
        return Observation(
            target_id=target_id, field=field, group=group, value=value,
            source=source, directness=Directness.INFERRED, url=url,
        )

    # -- Collector contract -------------------------------------------------
    def collect(self, target_id: str, seed: dict[str, str]) -> list[Observation]:
        client = self._get_client()
        if client is None:
            return []
        seen: set[tuple[str, str, str]] = set()
        obs: list[Observation] = []
        for q in self._queries(seed):
            try:
                resp = client.search(q, max_results=self.max_results, search_depth="basic")
            except Exception:
                continue
            for res in resp.get("results", []):
                for o in self._extract(target_id, seed, res):
                    key = (o.field, o.value, o.source)
                    if key not in seen:
                        seen.add(key)
                        obs.append(o)
        return obs
