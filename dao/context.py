"""Process-wide context: settings, config, signer, chain client, event log, node identity."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from xe.client import XeClient
from xe.pow import CHAT_POW_DIFFICULTY, DEFAULT_DIFFICULTY, parse_difficulty

from .config import Config, load_config, require_distinct_seats
from .log import EventLog
from .settings import Settings, get_settings
from .signer import Signer, SignerError

log = logging.getLogger("dao")


@dataclass
class NodeIdentity:
    network_id: str = ""
    node_id: str = ""
    version: str = ""
    pow_difficulty: int = DEFAULT_DIFFICULTY
    chat_pow_difficulty: int = CHAT_POW_DIFFICULTY

    @property
    def is_mainnet(self) -> bool:
        """Positive match only: `mainnet` or `mainnet-<n>`. Anything else (testnet-0005, devnet, unknown, empty)
        is shown as testnet, so a renamed or unexpected network can never be mistaken for the real one."""
        return self.network_id.split("-", 1)[0] == "mainnet"

    @property
    def badge(self) -> str:
        return "mainnet" if self.is_mainnet else "testnet"


@dataclass
class Context:
    settings: Settings
    config: Config
    signer: Signer
    chain: XeClient
    events: EventLog
    node: NodeIdentity = field(default_factory=NodeIdentity)

    async def refresh_node(self) -> NodeIdentity:
        try:
            info = await self.chain.node()
        except Exception as e:  # node unreachable at boot is survivable
            log.warning("node unreachable: %s", e)
            return self.node
        if not isinstance(info, dict):
            log.warning("node identity is not an object; keeping defaults")
            return self.node

        def difficulty(key: str, default: int) -> int:
            try:
                return parse_difficulty(info.get(key), default)
            except ValueError as e:   # a lying node is as survivable as an unreachable one (XE-0775)
                log.warning("node %s: %s; using default", key, e)
                return default

        # The network id goes under every signature a company key makes (blocks, the directory entry) and
        # into what a member's request is signed for. It is the deployment's, set by whoever deployed it,
        # and what the node says is compared with that and never adopted: a node URL pointed somewhere
        # else, or a node that says what it likes, would otherwise have the fee and dao keys signing for a
        # network of its choosing. On any other answer the identity has no network, and with no network
        # nothing is signed (`chainops.signed`, `job_directory`) and no signed request verifies (XE-12620).
        reported, expected = str(info.get("network_id", "")), self.settings.xe_network_id
        if not expected or reported != expected:
            log.error("the node at %s says it is network %r and this deployment is configured for %r "
                      "(XE_NETWORK_ID); nothing is signed until they match", self.settings.xe_node_url, reported, expected)
            reported = ""
        self.node = NodeIdentity(
            network_id=reported,
            node_id=str(info.get("id", "")),
            version=str(info.get("version", "")),
            pow_difficulty=difficulty("pow_difficulty", DEFAULT_DIFFICULTY),
            chat_pow_difficulty=difficulty("chat_pow_difficulty", CHAT_POW_DIFFICULTY),
        )
        return self.node

    @property
    def directory_node_peer(self) -> str:
        return self.settings.directory_node_peer or self.node.node_id

    async def aclose(self) -> None:
        await self.chain.aclose()


_ctx: Context | None = None


def build_context() -> Context:
    settings = get_settings()
    config = load_config(settings.config_dir)
    # The keyfile is the harness's identity: it signs the log every public reader verifies against. A service
    # that started without it would write a log that cannot be checked, so a missing file or wrong passphrase
    # stops the process here rather than running unsigned (XE-0494).
    try:
        signer = Signer.load(settings.signer_keyfile, settings.signer_passphrase)
    except SignerError as e:
        raise SystemExit(f"signer unavailable: {e}; the harness does not run without its keys") from e
    if not signer.has("harness"):
        raise SystemExit(f"{settings.signer_keyfile} has no 'harness' key; the log cannot be signed")
    config.signer_accounts = {n: signer.address(n) for n in ("dao", "fee") if signer.has(n)}
    require_distinct_seats(config)   # again, now the company's own accounts are known (XE-2073)
    chain = XeClient(settings.xe_node_url)
    events = EventLog(signer)
    return Context(settings=settings, config=config, signer=signer, chain=chain, events=events)


def get_context() -> Context:
    global _ctx
    if _ctx is None:
        _ctx = build_context()
    return _ctx


def set_context(ctx: Context) -> None:
    global _ctx
    _ctx = ctx
