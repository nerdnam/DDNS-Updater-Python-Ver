# /ddns-updater-python-ver-ipv4/ddns_updater/providers/base_provider.py
from abc import ABC, abstractmethod
import logging

class BaseProvider(ABC):
    NAME = "base" 

    def __init__(self, config: dict, logger: logging.Logger):
        self.config = config 
        self.logger = logger
        self.domain = config.get('domain') 
        self.owner = config.get('owner', '@')
        # self.api_timeout = config.get('http_timeout_seconds', 10) # 예시

    @abstractmethod
    def update_record(self, ip_address: str, record_type: str = "A", proxied: bool = None) -> tuple[bool, str]:
        pass

    @staticmethod
    @abstractmethod
    def get_required_config_fields() -> list[str]:
        pass

    @staticmethod
    def get_optional_config_fields() -> dict[str, any]:
        return {}

    @staticmethod
    @abstractmethod
    def get_description() -> str:
        pass

    def _get_fqdn(self) -> str:
        if self.owner == '@' or not self.owner:
            return self.domain
        return f"{self.owner}.{self.domain}"