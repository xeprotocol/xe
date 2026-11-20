"""Config as data: Schedule B, Schedule C, registry, charter, copy registers.

Loaded once at startup, hashed, and exposed read-only. A change to any file is a resolution matter;
the worker records the hash of each file in the log at boot so config history is itself a record.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from xe.keys import derive_address, exact_hex, is_valid_public_key


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class _OneOfEachName(yaml.SafeLoader):
    """YAML as `safe_load` reads it, except that a mapping which gives one name twice is refused. YAML
    keeps the last and says nothing, so a second `fee_micro_xe` further down a schedule replaced the
    first, and the check of names and domains (`require_valid_schedules`) saw one well-formed value and
    never the other: a name the file should not have there, which is what that check exists to refuse
    (XE-14108). A merge key (`<<`) is refused with it: what it merges in is spliced into the mapping
    without being read as one, so a name given twice inside it was taken, and a name it gives beside
    one the mapping gives is two values for one name whichever wins. No file here uses one."""

    def construct_mapping(self, node, deep=False):
        seen: set = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise ValueError(f"{Path(key_node.start_mark.name).name}: line {key_node.start_mark.line + 1} merges "
                                 f"another mapping in (`<<`); each name is given where it is read")
            key = self.construct_object(key_node, deep=True)
            try:
                twice = key in seen
                seen.add(key)
            except TypeError:   # an unhashable key, which the constructor below refuses in its own words
                continue
            if twice:
                raise ValueError(f"{Path(key_node.start_mark.name).name}: line {key_node.start_mark.line + 1} gives "
                                 f"{str(key)[:60]!r} a second time; a name is given once")
        return super().construct_mapping(node, deep)


def _load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return yaml.load(f, Loader=_OneOfEachName) or {}   # noqa: S506 (a SafeLoader)


def slugify(text: str) -> str:
    """'Legal & Compliance' -> 'legal-and-compliance'; used for seat page URLs."""
    return re.sub(r"[^a-z0-9]+", "-", text.lower().replace("&", " and ")).strip("-")


@dataclass(frozen=True)
class HumanSeat:
    id: str
    name: str
    kind: str          # member | officer
    role: str
    public_key: str
    may: tuple[str, ...]

    @property
    def slug(self) -> str:
        return self.id  # roles repeat between people (two founders); the id is the stable handle

    @property
    def account(self) -> str:
        return derive_address(self.public_key) if self.public_key else ""

    @property
    def is_member(self) -> bool:
        return self.kind == "member"

    def can(self, right: str) -> bool:
        return right in self.may


@dataclass(frozen=True)
class AgentSeat:
    id: str
    role: str
    cls: str
    status: str
    model: str
    account: str
    tool_scopes: tuple[str, ...]
    optional: bool = False
    summary: str = ""

    @property
    def slug(self) -> str:
        return slugify(self.role)


@dataclass
class Config:
    dir: Path
    schedule_b: dict
    schedule_c: dict
    registry: dict
    charter_md: str
    copy_public: dict
    copy_legal: dict
    kill_list: dict
    hashes: dict[str, str]
    prompts: dict[str, str]   # seat id (or "_preamble") -> markdown; config only, nothing calls a model in v1
    signer_accounts: dict[str, str] = field(default_factory=dict)   # name -> address, from the loaded keyfile

    # ---- seats ----------------------------------------------------------------------------

    @property
    def human_seats(self) -> list[HumanSeat]:
        out = []
        for s in self.schedule_c.get("human_seats", []):
            out.append(HumanSeat(
                id=s["id"], name=s.get("name", ""), kind=s.get("kind", "officer"), role=s.get("role", ""),
                public_key=(s.get("public_key") or "").lower(), may=tuple(s.get("may", [])),
            ))
        return out

    @property
    def members(self) -> list[HumanSeat]:
        return [s for s in self.human_seats if s.is_member]

    @property
    def agent_seats(self) -> list[AgentSeat]:
        out = []
        for s in self.schedule_c.get("agent_seats", []):
            out.append(AgentSeat(
                id=s["id"], role=s.get("role", ""), cls=s.get("class", "specialist"), status=s.get("status", "designed"),
                model=s.get("model", "") or "", account=(s.get("account") or "").lower(),
                tool_scopes=tuple(s.get("tool_scopes", [])), optional=bool(s.get("optional", False)),
                summary=" ".join((s.get("summary") or "").split()),
            ))
        return out

    def seat_page(self, slug: str) -> tuple[str, HumanSeat | AgentSeat] | None:
        """Resolve a /seats/{slug} path: agent role slug or seat id, or a human seat id."""
        slug = slug.lower()
        for a in self.agent_seats:
            if slug in (a.slug, a.id):
                return "agent", a
        for h in self.human_seats:
            if slug == h.id:
                return "human", h
        return None

    @property
    def tool_scope_glossary(self) -> dict[str, str]:
        return {k: str(v) for k, v in (self.schedule_c.get("tool_scopes") or {}).items()}

    def seat_by_key(self, public_key: str) -> HumanSeat | None:
        pk = public_key.lower()
        for s in self.human_seats:
            if s.public_key and s.public_key == pk:
                return s
        return None

    def seat(self, seat_id: str) -> HumanSeat | None:
        for s in self.human_seats:
            if s.id == seat_id:
                return s
        return None

    @property
    def agent_accounts(self) -> set[str]:
        return {s.account for s in self.agent_seats if s.account}

    @property
    def accounts(self) -> dict[str, str]:
        """The company's accounts by name. Schedule C may name them; the signer is authoritative for the
        ones it holds keys for (`dao`, `fee`), so a deployment that left the file blank still knows them
        and every reader of this property (fee checks, inbox, registers, the vote exclusion) agrees (XE-1479)."""
        out = {k: (v or "").lower() for k, v in (self.schedule_c.get("accounts") or {}).items()}
        out.update({k: v.lower() for k, v in self.signer_accounts.items() if v})
        return out

    @property
    def mode(self) -> str:
        return self.schedule_c.get("mode", "members-direct")

    # ---- schedule B accessors --------------------------------------------------------------

    @property
    def open_vote(self) -> dict:
        return self.schedule_b.get("open_vote", {})

    @property
    def windows(self) -> dict:
        return self.schedule_b.get("windows", {})

    @property
    def pause(self) -> dict:
        return self.schedule_b.get("pause", {})

    @property
    def cadence(self) -> dict:
        return self.schedule_b.get("cadence", {})

    def excluded_accounts(self) -> set[str]:
        """Accounts whose vote weighs nothing: the company's own (treasury, fee, dao) and any Schedule B
        names. Agent seats are not here: their weight is bounded by `agents.max_weight_share` in the tally
        and their participation by `exclude_agent_accounts`; zeroing them would make both dead (XE-1479)."""
        ex = {a.lower() for a in self.open_vote.get("excluded_accounts", []) if a}
        for name in ("treasury", "fee", "dao"):
            a = self.accounts.get(name)
            if a:
                ex.add(a)
        return ex

    def pinned_rules(self) -> dict:
        """The rules snapshot pinned to a proposal when it opens."""
        ov = self.open_vote
        return {
            "window_days": self.windows.get("open_vote_days", 21),
            "quorum_wallets": ov.get("quorum_wallets", 20),
            "participating_wallet": ov.get("participating_wallet", {}),
            "pass_mark_fraction": ov.get("pass_mark_fraction", 0.5),
            "weight_asset": ov.get("weight_asset", "XE"),
            "fee_micro_xe": ov.get("fee_micro_xe", 0),
            "fee_on_quorum": ov.get("fee_on_quorum", "refund"),
            "fee_below_quorum": ov.get("fee_below_quorum", "burn"),
            "agents": ov.get("agents", {}),
            "excluded_accounts": sorted(self.excluded_accounts()),
            "schedule_b_hash": self.hashes.get("schedule_b.yaml", ""),
        }

    @property
    def charter_hash(self) -> str:
        return hashlib.sha256(self.charter_md.encode("utf-8")).hexdigest()

    def prompt_hash(self, seat_id: str) -> str:
        """Hash of preamble + seat prompt, i.e. of what the seat would actually be given."""
        pre = self.prompts.get("_preamble", "")
        body = self.prompts.get(seat_id)
        if body is None:
            return ""
        return hashlib.sha256((pre + "\n\n" + body).encode("utf-8")).hexdigest()


def load_config(config_dir: Path) -> Config:
    d = Path(config_dir)
    files = {
        "schedule_b.yaml": d / "schedule_b.yaml",
        "schedule_c.yaml": d / "schedule_c.yaml",
        "registry.yaml": d / "registry.yaml",
        "charter.md": d / "charter.md",
        "copy/public.yaml": d / "copy" / "public.yaml",
        "copy/legal.yaml": d / "copy" / "legal.yaml",
        "copy/kill_list.yaml": d / "copy" / "kill_list.yaml",
    }
    missing = [k for k, p in files.items() if not p.exists()]
    if missing:
        raise FileNotFoundError(f"config files missing in {d}: {missing}")
    prompts: dict[str, str] = {}
    prompts_dir = d / "prompts"
    if prompts_dir.is_dir():
        for p in sorted(prompts_dir.glob("*.md")):
            prompts[p.stem] = p.read_text(encoding="utf-8")
            files[f"prompts/{p.name}"] = p
    cfg = _read_config(d, files, prompts)
    require_distinct_seats(cfg)
    require_valid_schedules(cfg)
    return cfg


def require_distinct_seats(cfg: Config) -> None:
    """Refuse a Schedule C whose seats are not each one identity (`seat_conflicts`), with one kind of error
    whatever is wrong with it. Called when the config is loaded, and again by `build_context` once the
    keyfile has said which accounts the company holds, since a seat must not be one of those either."""
    try:
        conflicts = seat_conflicts(cfg)
    except (KeyError, TypeError, AttributeError) as e:   # a seat that is not a mapping, or has no id, or a number for one
        raise ValueError(f"schedule_c.yaml: a seat entry is malformed ({type(e).__name__}: {e})") from e
    if conflicts:
        raise ValueError("schedule_c.yaml: " + "; ".join(conflicts))


def seat_conflicts(cfg: Config) -> list[str]:
    """Every seat is one identity: its id, its page handle, its key and its account each name that seat and
    no other. Everything that resolves a seat takes the first match (`seat_by_key`, `seat`, `seat_page`) and
    everything that counts seats counts the list (thresholds, quorum of members), so two seats sharing an
    identity leave one that is counted and can never act, or two people signing into one slot, and nothing
    says so (XE-2073). A Schedule C like that is refused at load, by the API, the worker and the CLI alike,
    since all three come through `load_config`. A blank key or account is a seat not yet filled, not a
    conflict.

    An id is the seat's handle everywhere (its page, the log, a stored signature), so it is there, and it
    is lower-case letters, digits and hyphens: `seat_page` looks a seat up by the lower-cased path, and an
    id it cannot spell is a seat with no page. An agent seat's page is also reached by its role, so the
    role has to make a handle. And a seat's account is not one of the company's own (treasury, fee, dao):
    those are excluded from every vote and are what the harness itself signs as, so a seat on one of them
    is two identities in one account."""
    out: list[str] = []
    handles: dict[str, str] = {}
    keys: dict[str, str] = {}
    accounts: dict[str, str] = {}
    hex64 = re.compile(r"[0-9a-f]{64}")

    def claim(taken: dict[str, str], value: str, seat: str, what: str) -> bool:
        if value and taken.setdefault(value, seat) != seat:
            out.append(f"{what} {value[:16]} is used by both {taken[value]} and {seat}")
            return False
        return True

    def handle(seat_id, seat: str) -> bool:
        if not isinstance(seat_id, str) or not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", seat_id):
            out.append(f"{seat}: id must be lower-case letters, digits and hyphens")
            return False
        return claim(handles, seat_id, seat, "seat id")

    for name, account in sorted(cfg.accounts.items()):
        accounts.setdefault(account, f"the company's {name} account")   # two names for one company account is not a seat's business
    accounts.pop("", None)
    for i, h in enumerate(cfg.human_seats):
        seat = f"human seat {i + 1} ({h.id})"
        handle(h.id, seat)
        if h.public_key and not hex64.fullmatch(h.public_key):
            out.append(f"{seat}: public_key is not 64 hex characters")
            continue
        if claim(keys, h.public_key, seat, "public key"):   # a shared key is a shared account; said once
            claim(accounts, h.account, seat, "account")
    for i, a in enumerate(cfg.agent_seats):
        seat = f"agent seat {i + 1} ({a.id})"
        handle(a.id, seat)
        if not a.slug:
            out.append(f"{seat}: role is blank, so the seat has no page")
        elif a.slug != a.id:
            claim(handles, a.slug, seat, "seat page")
        if a.account and not hex64.fullmatch(a.account):
            out.append(f"{seat}: account is not 64 hex characters")
            continue
        claim(accounts, a.account, seat, "account")
    return out


# ---- the domain of each schedule value ---------------------------------------------------------------
#
# A schedule value the code turns into a time, an amount, a state or a set of people is in its domain when
# the config is loaded, or the config is not loaded. The code reads these values where it uses them
# (`int(c.get(...))`, `f"due_{action}"`, `kind == "member"`), and before this a value outside its domain
# was used as written: a misspelt fee action left every fee in a state no worker reads, an hour of 24
# stopped every scheduled job, `kind: Member` took a founder out of every consent set, and nothing said
# so (XE-3160 and the value-by-value reports after it). The API, the worker and the CLI all come through
# `load_config`, so one check here is the check for all three. A key that is absent takes the code's
# default, which is in the domain; a key that is present is checked.
#
# A key that is present is also one the file has. The first version of this checked every value it knew
# and looked at no name it did not: `knd: member` on a founder's seat, `treasuy:` under accounts or
# `open_vot:` at the top loaded cleanly, the real key was absent, and the default stood in for what the
# members had written, which is the failure above by the other spelling (XE-14108). So every mapping in
# the two schedules is closed: the tables below name its keys, and a name that is not there refuses the
# load. That includes the parts the code only publishes (the thresholds, the two lists of what the agents
# decide), which are in the tables with the shape their readers assume (XE-14107).

U64_MAX = 2**64 - 1
FEE_ACTIONS = ("refund", "burn")                       # `fees.DUE` is `due_` + each
WEIGHT_ASSETS = ("XE",)                                # balances, the fee and the floor are all in µXE
TIMELOCK_STATUSES = ("proposed", "active")
SEAT_KINDS = ("member", "officer")
SEAT_RIGHTS = ("reserved_matters", "pause", "sign_statechain", "sign_treasury", "sign_resolutions", "sign_operations",
               "operational_review")
AGENT_CLASSES = ("orchestrator", "specialist")
AGENT_STATUSES = ("designed", "designated", "active", "retired")
MODES = ("members-direct", "ensemble")
_HEX64_ANY = re.compile(r"[0-9a-fA-F]{64}")


def _whole(lo: int, hi: int):
    return (lambda v: type(v) is int and lo <= v <= hi), f"a whole number from {lo} to {hi}"


def _one_of(names: tuple[str, ...]):
    return (lambda v: type(v) is str and v in names), "one of " + ", ".join(names)


def _flag():
    return (lambda v: type(v) is bool), "true or false"


def _strings(ok, words: str, *, empty: bool):
    def check(v) -> bool:
        return (isinstance(v, list) and (empty or bool(v)) and all(type(x) is str and ok(x) for x in v)
                and len(set(v)) == len(v))
    return check, words


def _text():
    return (lambda v: type(v) is str and bool(v.strip())), "a word or a phrase"


def _phrases():
    return _strings(lambda x: bool(x.strip()), "a list of distinct phrases", empty=True)


def _unknown(where: str, section: dict, known) -> list[str]:
    """The names in `section` that are not among `known`, each as a fault that says which names are."""
    known = sorted(known)
    return [f"{where}{str(key)[:60]!r} is not a name this file has there; the names are {', '.join(known)}"
            for key in section if key not in known]


# Section by section, the keys Schedule B has and the domain of each. "" is the top of the file; a
# dotted name is a section inside a section, and is itself a key of the one it is in.
SCHEDULE_B_DOMAINS: dict[str, dict[str, tuple]] = {
    "": {
        "version": _whole(1, 10**6),
        "agents_decide": _phrases(),
        "agents_do_not_decide": _phrases(),
        "agent_budget_micro_xe": _whole(0, U64_MAX),
    },
    "quorums": {"member": _text(), "specialist_agents": _text()},
    "thresholds": {"reserved_matters": _text(), "other_oa_rules": _text()},
    "thresholds.charter_core_principles": {
        "members_fraction": ((lambda v: type(v) in (int, float) and 0 < v <= 1), "a number above 0, up to 1"),
        "specialists": _text(),
    },
    "cadence": {
        "health_check_minutes": _whole(1, 60),
        "directory_reregister_minutes": _whole(1, 29),      # inside the node's 30-minute directory TTL
        "daily_note_hour_utc": _whole(0, 23),
        "weekly_review_weekday": _whole(1, 7),              # Monday = 1 ... Sunday = 7
        "weekly_review_hour_utc": _whole(0, 23),
        "anchor_weekday": _whole(1, 7),
        "anchor_hour_utc": _whole(0, 23),
        "monthly_report_day": _whole(1, 28),                # a day every month has
    },
    "windows": {
        "open_vote_days": _whole(1, 365),
        "protocol_parameter_days": _whole(1, 365),
        "reserved_matter": _text(),
        "upgrade_timelock_hours": _whole(0, 8760),
        "upgrade_timelock_status": _one_of(TIMELOCK_STATUSES),
    },
    "pause": {
        "initial_hours": _whole(1, 8760),
        "extension_days": _whole(1, 365),
        "public_post_within_hours": _whole(1, 8760),
        "grounds": _strings(lambda x: bool(x.strip()), "a list of distinct grounds, at least one", empty=False),
    },
    "open_vote": {
        "fee_micro_xe": _whole(0, 2**63 - 1),   # kept in the fee ledger, whose column is a signed 64-bit integer
        "fee_on_quorum": _one_of(FEE_ACTIONS),
        "fee_below_quorum": _one_of(FEE_ACTIONS),
        "quorum_wallets": _whole(1, 10**9),
        "pass_mark_fraction": ((lambda v: type(v) in (int, float) and 0 <= v < 1), "a number from 0 up to, not including, 1"),
        "weight_asset": _one_of(WEIGHT_ASSETS),
        "excluded_accounts": _strings(lambda x: bool(_HEX64_ANY.fullmatch(x)), "a list of distinct 64-hex accounts", empty=True),
    },
    "open_vote.participating_wallet": {
        "min_balance_micro_xe": _whole(0, U64_MAX),
        "must_exist_before_open": _flag(),
        "exclude_agent_accounts": _flag(),
    },
    "open_vote.agents": {
        "stipend_micro_xe": _whole(0, U64_MAX),
        "max_weight_share": ((lambda v: type(v) in (int, float) and 0 <= v <= 1), "a number from 0 to 1"),
        "count_toward_quorum": _flag(),
    },
}


def schedule_b_faults(cfg: Config) -> list[str]:
    """Every Schedule B name the file does not have and every value that is outside its domain
    (`SCHEDULE_B_DOMAINS`), in the file's own words."""
    out: list[str] = []
    if not isinstance(cfg.schedule_b, dict):
        return ["the file is not a mapping"]
    for path, domain in SCHEDULE_B_DOMAINS.items():
        section: Any = cfg.schedule_b
        for name in (path.split(".") if path else ()):
            section = section.get(name, {}) if isinstance(section, dict) else None
        if not isinstance(section, dict):
            out.append(f"{path} must be a mapping")
            continue
        where = f"{path}." if path else ""
        inside = {p.rpartition(".")[2] for p in SCHEDULE_B_DOMAINS if p and p.rpartition(".")[0] == path}
        out += _unknown(where, section, set(domain) | inside)
        for key, (ok, words) in domain.items():
            if key in section and not ok(section[key]):
                out.append(f"{where}{key} is {section[key]!r}; it must be {words}")
    # One matter is in one of the two lists. In both, the page that prints them said the agents decide it
    # and do not, and each list was well formed on its own (XE-14107).
    lists = [cfg.schedule_b.get(k) for k in ("agents_decide", "agents_do_not_decide")]
    if all(_phrases()[0](x) for x in lists):
        both = sorted({p.strip().lower() for p in lists[0]} & {p.strip().lower() for p in lists[1]})
        if both:
            out.append(f"agents_decide and agents_do_not_decide both hold {', '.join(repr(p[:60]) for p in both)}; "
                       "a matter is in one of them")
    w = cfg.schedule_b.get("windows")
    if isinstance(w, dict) and w.get("upgrade_timelock_status") == "active" and w.get("upgrade_timelock_hours", 0) == 0:
        out.append("windows.upgrade_timelock_status is active with upgrade_timelock_hours of 0: an armed timelock runs for at least an hour")
    return out


# The keys Schedule C has, mapping by mapping. `accounts` names the three accounts the code reads; a
# fourth name there is read by nothing.
SCHEDULE_C_KEYS: dict[str, tuple[str, ...]] = {
    "": ("version", "mode", "repository", "human_seats", "agent_seats", "tool_scopes", "model_candidates", "accounts"),
    "repository": ("url", "licence", "audit"),
    "accounts": ("dao", "fee", "treasury"),
    "human seat": ("id", "name", "kind", "role", "public_key", "may"),
    "agent seat": ("id", "role", "class", "status", "model", "account", "tool_scopes", "optional", "summary"),
}


def schedule_c_faults(cfg: Config) -> list[str]:
    """Every name in Schedule C the file does not have (`SCHEDULE_C_KEYS`) and every seat attribute that
    is outside its vocabulary, read from the file as written (the `human_seats` property turns
    `may: pause` into a tuple of letters, and a seat whose `kind` is not exactly `member` into an
    officer). A seat's key, where given, is one a signature can verify under: a seat that is counted and
    can never sign is the deadlock of XE-2073 by another spelling."""
    out: list[str] = []
    if not isinstance(cfg.schedule_c, dict):
        return ["the file is not a mapping"]
    out += _unknown("", cfg.schedule_c, SCHEDULE_C_KEYS[""])
    repository = cfg.schedule_c.get("repository")
    if repository is not None and not isinstance(repository, dict):
        out.append("repository must be a mapping")
    out += _unknown("repository.", repository if isinstance(repository, dict) else {}, SCHEDULE_C_KEYS["repository"])
    candidates = cfg.schedule_c.get("model_candidates")
    if candidates is not None and not _phrases()[0](candidates):
        out.append(f"model_candidates is {candidates!r}; it must be {_phrases()[1]}")
    if "version" in cfg.schedule_c and not _whole(1, 10**6)[0](cfg.schedule_c["version"]):
        out.append(f"version is {cfg.schedule_c['version']!r}; it must be {_whole(1, 10**6)[1]}")
    if "mode" in cfg.schedule_c and not _one_of(MODES)[0](cfg.schedule_c["mode"]):
        out.append(f"mode is {cfg.schedule_c['mode']!r}; it must be one of {', '.join(MODES)}")
    for i, s in enumerate(cfg.schedule_c.get("human_seats") or []):
        seat = f"human seat {i + 1} ({s.get('id')})"
        out += _unknown(f"{seat}: ", s, SCHEDULE_C_KEYS["human seat"])
        if "kind" in s and not _one_of(SEAT_KINDS)[0](s["kind"]):
            out.append(f"{seat}: kind is {s['kind']!r}; it must be one of {', '.join(SEAT_KINDS)}")
        if "may" in s and not _strings(lambda x: x in SEAT_RIGHTS, "", empty=True)[0](s["may"]):
            out.append(f"{seat}: may is {s['may']!r}; it must be a list of distinct rights from {', '.join(SEAT_RIGHTS)}")
        key = s.get("public_key") or ""
        if isinstance(key, str) and _HEX64_ANY.fullmatch(key) and not is_valid_public_key(exact_hex(key, 32, "public key")):
            out.append(f"{seat}: public_key is not a usable ed25519 key")
    accounts = cfg.schedule_c.get("accounts")
    if accounts is not None and not isinstance(accounts, dict):
        out.append("accounts must be a mapping of names to accounts")
    out += _unknown("accounts.", accounts if isinstance(accounts, dict) else {}, SCHEDULE_C_KEYS["accounts"])
    for name, account in (accounts.items() if isinstance(accounts, dict) else ()):
        # every signed request is addressed to `dao`, fees are paid to `fee`, and the vote leaves these
        # out of the weight: a value that is no account is one nothing on the chain can ever match
        if name in SCHEDULE_C_KEYS["accounts"] and account not in (None, "") and not (isinstance(account, str) and _HEX64_ANY.fullmatch(account)):
            out.append(f"accounts.{name} is {account!r}; it must be a 64-hex account, or left empty")
    scopes = cfg.schedule_c.get("tool_scopes")
    if scopes is not None and not isinstance(scopes, dict):
        out.append("tool_scopes must be a mapping of scope names to what each allows")
    for i, s in enumerate(cfg.schedule_c.get("agent_seats") or []):
        seat = f"agent seat {i + 1} ({s.get('id')})"
        out += _unknown(f"{seat}: ", s, SCHEDULE_C_KEYS["agent seat"])
        for key, names in (("class", AGENT_CLASSES), ("status", AGENT_STATUSES)):
            if key in s and not _one_of(names)[0](s[key]):
                out.append(f"{seat}: {key} is {s[key]!r}; it must be one of {', '.join(names)}")
        if "optional" in s and type(s["optional"]) is not bool:
            out.append(f"{seat}: optional is {s['optional']!r}; it must be true or false")
        # from the glossary, which has to be there for a seat to name one: with none, every name passed
        if "tool_scopes" in s and not _strings(lambda x: isinstance(scopes, dict) and x in scopes, "", empty=True)[0](s["tool_scopes"]):
            out.append(f"{seat}: tool_scopes is {s['tool_scopes']!r}; it must be a list of distinct scopes from the glossary")
    return out


def require_valid_schedules(cfg: Config) -> None:
    """Refuse a config whose schedules carry a name they do not have or a value outside its domain, naming every one. Called by
    `load_config` after the seats are known to be well formed (`require_distinct_seats`)."""
    faults = [f"schedule_b.yaml: {f}" for f in schedule_b_faults(cfg)] + [f"schedule_c.yaml: {f}" for f in schedule_c_faults(cfg)]
    if faults:
        raise ValueError("; ".join(faults))


def _read_config(d: Path, files: dict[str, Path], prompts: dict[str, str]) -> Config:
    return Config(
        dir=d,
        schedule_b=_load_yaml(files["schedule_b.yaml"]),
        schedule_c=_load_yaml(files["schedule_c.yaml"]),
        registry=_load_yaml(files["registry.yaml"]),
        charter_md=files["charter.md"].read_text(encoding="utf-8"),
        copy_public=_load_yaml(files["copy/public.yaml"]),
        copy_legal=_load_yaml(files["copy/legal.yaml"]),
        kill_list=_load_yaml(files["copy/kill_list.yaml"]),
        hashes={k: _sha256_file(p) for k, p in files.items()},
        prompts=prompts,
    )


# ---- copy lint -------------------------------------------------------------------------------

def _flatten_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _flatten_strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _flatten_strings(v)]
    return []


# Every template is in one register. The public ones are linted against the kill list by every gate there is
# (`dao copy-lint`, the test suite), from this list and no other: the command once carried a shorter list of
# its own and passed pages the tests would have failed (XE-5986).
PUBLIC_TEMPLATES = ("base.html", "home.html", "proposals.html", "proposal.html", "proposal_new.html", "seats.html",
                    "seat.html", "how.html", "decisions.html", "decision_record.html", "inbox.html", "log.html",
                    "log_entry.html", "live.html", "charter.html", "error.html", "_keybox.html", "_rules.html")
LEGAL_TEMPLATES = ("members.html", "records.html")   # the seat holders' console and the statutory records
TEMPLATE_DIR = Path(__file__).parent / "templates"


def template_prose(text: str) -> str:
    """What a template says to a reader: Jinja, scripts and tags removed."""
    text = re.sub(r"{[{%#].*?[}%#]}", " ", text, flags=re.S)
    text = re.sub(r"<script.*?</script>", " ", text, flags=re.S)
    return re.sub(r"<[^>]+>", " ", text)


def public_template_prose() -> list[str]:
    return [template_prose((TEMPLATE_DIR / name).read_text(encoding="utf-8")) for name in PUBLIC_TEMPLATES]


def lint_public_copy(cfg: Config, extra_texts: list[str] | None = None) -> list[str]:
    """Return a list of violations (empty means clean)."""
    phrases = [p.lower() for p in cfg.kill_list.get("phrases", [])]
    words = [w.lower() for w in cfg.kill_list.get("words", [])]
    texts = _flatten_strings(cfg.copy_public) + list(extra_texts or [])
    violations: list[str] = []
    for t in texts:
        low = t.lower()
        for p in phrases:
            if p in low:
                violations.append(f"phrase {p!r} in: {t[:80]!r}")
        for w in words:
            if re.search(rf"(?<![a-z0-9]){re.escape(w)}(?![a-z0-9])", low):
                violations.append(f"word {w!r} in: {t[:80]!r}")
    return violations
