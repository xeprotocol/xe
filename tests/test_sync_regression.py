"""
Regression test for Issue #371:
[Desk] sync._other_live_patches drops a manually-fixing ticket out of fixing
while another maintainer's Fixes #n PR is still open.
"""

import asyncio
import unittest
from types import SimpleNamespace
from dataclasses import dataclass


@dataclass
class Ticket:
    id: str
    kind: str
    visibility: str
    status: str


@dataclass
class PatchRef:
    ticket_id: str
    repo: str
    ref: str
    kind: str
    state: str
    author: str
    followed: str
    moved_from: str


async def _other_live_patches(ctx, db, t, repo, ref):
    q = [
        p
        for p in db.patches
        if p.ticket_id == t.id
        and p.kind == "pr"
        and p.state in ("open", "merged")
        and not (p.repo == repo and p.ref == ref)
    ]
    bot = ctx.settings.github_bot_login
    for other in q:
        if (
            other.state == "merged"
            or other.moved_from
            or other.followed == "open"
            or (bot and other.author == bot)
        ):
            return True
    return False


async def _follow_pull_state(ctx, db, t, pr, state, trusted=False):
    if state == "open":
        if not trusted:
            return False
        if pr.followed != "open":
            pr.followed = "open"
        if t.status == "fixing":
            if not pr.moved_from:
                pr.moved_from = ""
            return False
        target = "fixing"
    else:
        if t.status != "fixing" or not (trusted or pr.moved_from):
            return False
        if await _other_live_patches(ctx, db, t, pr.repo, pr.ref):
            return False
        target = pr.moved_from or "accepted"
    t.status = target
    return True


class TestSyncOtherLivePatches(unittest.TestCase):
    def test_other_live_patches_counts_followed_open_maintainer_pr(self):
        async def run_scenario():
            t = Ticket(id="XE-0042", kind="bounty", visibility="public", status="fixing")
            pr1 = PatchRef("XE-0042", "xeprotocol/xe", "10", "pr", "open", "alice", "", "")
            pr2 = PatchRef("XE-0042", "xeprotocol/xe", "11", "pr", "open", "bob", "", "")
            stranger = PatchRef("XE-0042", "xeprotocol/xe", "12", "pr", "open", "rando", "", "")
            mention = PatchRef("XE-0042", "xeprotocol/xe", "13", "pr", "open", "alice", "", "")

            ctx = SimpleNamespace(settings=SimpleNamespace(github_bot_login=""))
            db = SimpleNamespace(patches=[pr2, stranger, mention])

            # Ticket was already at `fixing` before either maintainer PR opened (`moved_from == ""`).
            res1 = await _follow_pull_state(ctx, db, t, pr1, "open", trusted=True)
            res2 = await _follow_pull_state(ctx, db, t, pr2, "open", trusted=True)
            self.assertFalse(res1)
            self.assertFalse(res2)
            self.assertEqual(pr1.followed, "open")
            self.assertEqual(pr1.moved_from, "")
            self.assertEqual(pr2.followed, "open")
            self.assertEqual(pr2.moved_from, "")

            # Stranger's PR is ignored; bare mention PR never enters _follow_pull_state
            res_stranger = await _follow_pull_state(ctx, db, t, stranger, "open", trusted=False)
            self.assertFalse(res_stranger)
            self.assertEqual(stranger.followed, "")
            self.assertEqual(mention.followed, "")

            # Closing pr1 unmerged while pr2 (followed == "open") is still open must NOT drop t from fixing.
            pr1.state = "closed"
            res_close1 = await _follow_pull_state(ctx, db, t, pr1, "closed", trusted=True)
            self.assertFalse(res_close1)
            self.assertEqual(t.status, "fixing")

            # Once pr2 also closes unmerged (leaving only stranger and mention open), t drops to accepted.
            db.patches = [stranger, mention]
            pr2.state = "closed"
            res_close2 = await _follow_pull_state(ctx, db, t, pr2, "closed", trusted=True)
            self.assertTrue(res_close2)
            self.assertEqual(t.status, "accepted")

        asyncio.run(run_scenario())


if __name__ == "__main__":
    unittest.main()
