"""Outbound feature boundary; internal authentication and database I/O are separate."""
from .config import get_settings


def offline_mode(settings=None) -> bool:
    settings = settings or get_settings()
    return bool(getattr(settings, "offline_mode", False))


def require_online(feature: str, settings=None) -> None:
    if offline_mode(settings):
        raise RuntimeError(f"폐쇄망 모드에서 {feature} 외부 호출이 차단되었습니다")
