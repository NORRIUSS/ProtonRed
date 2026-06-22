from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import AsyncGenerator, Optional


@dataclass
class Message:
    role: str  # system | user | assistant
    content: str


@dataclass
class ProviderConfig:
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    extra: dict = field(default_factory=dict)


class AIProvider(ABC):
    @abstractmethod
    async def complete(self, messages: list[Message], temperature: float = 0.7, max_tokens: int = 4096) -> str:
        pass

    @abstractmethod
    async def stream(self, messages: list[Message], temperature: float = 0.7, max_tokens: int = 4096) -> AsyncGenerator[str, None]:
        pass

    @property
    @abstractmethod
    def model_id(self) -> str:
        pass
