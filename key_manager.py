import os
import asyncio
from itertools import cycle
from typing import Optional


class GeminiKeyManager:
    def __init__(self):
        self.keys = self._load_keys()
        self._cycle = cycle(range(len(self.keys)))
        self._exhausted = set()
        self._lock = asyncio.Lock()

        if not self.keys:
            raise ValueError("No GEMINI_API_KEY_* found in environment.")
        print(f"✓ Loaded {len(self.keys)} Gemini API keys")

    def _load_keys(self) -> list:
        keys = []
        for i in range(1, 11):
            k = os.getenv(f"GEMINI_API_KEY_{i}")
            if k:
                keys.append(k)
        if not keys:
            single = os.getenv("GEMINI_API_KEY")
            if single:
                keys.append(single)
        return keys

    async def get_key(self) -> Optional[str]:
        async with self._lock:
            if len(self._exhausted) >= len(self.keys):
                print("✗ All Gemini API keys exhausted!")
                return None

            for _ in range(len(self.keys)):
                idx = next(self._cycle)
                if idx not in self._exhausted:
                    return self.keys[idx]
            return None

    async def mark_exhausted(self, key: str):
        async with self._lock:
            try:
                idx = self.keys.index(key)
                self._exhausted.add(idx)
                remaining = len(self.keys) - len(self._exhausted)
                print(f"⚠ Key #{idx+1} marked exhausted. {remaining} keys remaining.")
            except ValueError:
                pass

    async def reset(self):
        async with self._lock:
            self._exhausted.clear()
            self._cycle = cycle(range(len(self.keys)))
            print("✓ All API keys reset.")

    @property
    def status(self) -> dict:
        return {
            "total": len(self.keys),
            "exhausted": len(self._exhausted),
            "active": len(self.keys) - len(self._exhausted)
        }


key_manager = GeminiKeyManager()