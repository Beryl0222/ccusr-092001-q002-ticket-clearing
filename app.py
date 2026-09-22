"""服务装配：领域口径 + 存储 + 核心逻辑 + 清算。"""

from __future__ import annotations

from pathlib import Path

from clearing import Clearing
from core import Core
from domain import load
from store import Store


class System:
    def __init__(self, db_path: str | Path = ":memory:",
                 domain_path: str | Path | None = None, clock=None):
        self.domain = load(domain_path) if domain_path else load()
        self.store = Store(db_path)
        kwargs = {"clock": clock} if clock is not None else {}
        self.core = Core(self.store, self.domain, **kwargs)
        self.clearing = Clearing(self.core)

    def close(self):
        self.store.close()
