"""Instaloader wrapper: Instagram public profile -> full name (needs a session).

Instagram redirects anonymous profile requests to a login page, so this collector needs an
Instaloader session file (``instaloader --login <you>``) at ``INSTAGRAM_SESSIONFILE``. It
is a no-op without one.
"""

from __future__ import annotations

import os

from osint_ai_pwg.collect.base import Collector
from osint_ai_pwg.schemas import Directness, FieldGroup, Observation


class InstaloaderCollector(Collector):
    name = "instaloader"

    def collect(self, target_id: str, seed: dict[str, str]) -> list[Observation]:
        user = seed.get("username")
        sessionfile = os.environ.get("INSTAGRAM_SESSIONFILE")
        if not user or not sessionfile:
            return []
        try:
            import instaloader

            loader = instaloader.Instaloader()  # type: ignore[attr-defined]
            loader.load_session_from_file(user, sessionfile=sessionfile)
            profile = instaloader.Profile.from_username(loader.context, user)  # type: ignore[attr-defined]
        except Exception:  # no session / login wall / rate limit
            return []

        obs: list[Observation] = []
        if profile.full_name:
            obs.append(Observation(target_id, "name", FieldGroup.IDENTITY,
                                   profile.full_name, "instaloader:profile",
                                   Directness.STATED, url=profile.profile_url))
        return obs
