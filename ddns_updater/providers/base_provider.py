# /ddns-updater-python-ver-ipv4/ddns_updater/providers/base_provider.py
from abc import ABC, abstractmethod
from typing import Any
import logging
import re

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
    def get_optional_config_fields() -> dict[str, Any]:
        return {}

    @staticmethod
    @abstractmethod
    def get_description() -> str:
        pass

    def _get_fqdn(self) -> str:
        if self.owner == '@' or not self.owner:
            return self.domain
        return f"{self.owner}.{self.domain}"

    @staticmethod
    def sanitize_error(exc) -> str:
        """예외/오류 메시지에서 URL userinfo(user:pass@)와 쿼리 문자열을 마스킹한다.

        일부 프로바이더는 자격증명을 URL 쿼리 파라미터나 userinfo로 전달하는데,
        requests 예외 메시지에는 요청 URL이 포함될 수 있어 그대로 로그에 남기면
        비밀번호/토큰이 유출된다.
        """
        text = str(exc)
        text = re.sub(r'//[^/@\s]+:[^/@\s]+@', '//***:***@', text)
        text = re.sub(r'\?[^\s\'")\]]+', '?<query-redacted>', text)
        return text