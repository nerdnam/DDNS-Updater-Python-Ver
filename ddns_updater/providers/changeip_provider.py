# ddns_updater/providers/changeip_provider.py
import requests

from .base_provider import BaseProvider

class ChangeipProvider(BaseProvider):
    NAME = "changeip"
    API_ENDPOINT = "https://nic.ChangeIP.com/nic/update"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.username = self.config.get('changeip_username')
        self.password = self.config.get('changeip_password')
        # self.domain, self.owner 는 BaseProvider 에서 처리

        # 필수 설정값 확인
        if not all([self.username, self.password, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (changeip_username, changeip_password, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

    @staticmethod
    def get_required_config_fields():
        # owner는 ChangeIP에서 필수이지만, DynDNS 표준에서는 선택적일 수 있음.
        # BaseProvider에서 owner의 기본값을 '@'로 처리하므로, 여기서는 명시.
        return ["changeip_username", "changeip_password", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        return {"ttl": None} # ChangeIP API가 TTL 설정을 지원하는지 확인 필요

    @staticmethod
    def get_description():
        return "Updates DNS records on ChangeIP.com using their DynDNS API."

    def _build_hostname(self):
        """Go 코드의 utils.BuildURLQueryHostname과 유사하게 호스트명 구성"""
        owner = self.config.get('owner', '@')
        if owner == '@' or owner == '' or owner is None: # owner가 없거나 @이면 domain만 사용
            return self.domain
        return f"{owner}.{self.domain}"

    def update_record(self, ip_address, record_type="A", proxied=None):
        # ChangeIP는 IPv4/IPv6 구분 없이 'ip' 파라미터를 사용하고,
        # record_type (A/AAAA)은 API 요청에 직접 사용되지 않음.
        # 다만, 로깅이나 내부 로직에서는 record_type을 활용할 수 있음.
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        hostname = self._build_hostname()
        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update {hostname} (record type {record_type}) to IP: {ip_address}")

        params = {
            'hostname': hostname,
            'ip': ip_address
        }

        auth = (self.username, self.password) # HTTP Basic Authentication
        headers = {'User-Agent': f'Python-DDNS-Updater/{self.NAME}'}
        timeout = self.config.get('http_timeout_seconds', 10)

        try:
            response = requests.get(self.API_ENDPOINT, params=params, auth=auth, headers=headers, timeout=timeout)
            
            response_text = response.text.strip() if response.text else ""
            self.logger.debug(f"{self.NAME.capitalize()} API Response Status: {response.status_code}, Body: '{response_text}'")

            # ChangeIP API는 성공 시 상태 코드 200을 반환하고,
            # 응답 본문은 성공/실패 메시지를 포함할 수 있음 (예: "OK", "Update successful", 또는 오류 메시지)
            # Go 코드는 상태 코드 200이면 본문 내용과 관계없이 성공으로 간주.
            # 좀 더 안전하게 하려면, 성공 응답 본문에 특정 키워드가 있는지 확인하는 것이 좋음.
            # (예: "good", "nochg", "success", 또는 ChangeIP 문서에 명시된 성공 응답)
            # 여기서는 Go 코드의 단순함을 따라 상태 코드 200이면 성공으로 처리.
            if response.status_code == 200:
                # 성공 메시지를 좀 더 구체적으로 만들 수 있다면 좋음.
                # 예: "Successfully updated {hostname} to {ip_address}. API Response: {response_text}"
                # 하지만 API가 업데이트된 IP를 반환하지 않으므로, 요청한 IP로 업데이트되었다고 가정.
                success_message = f"Successfully updated {hostname} to {ip_address} (assumed, API status 200)."
                if response_text: # 응답 본문이 있다면 로그에 포함
                    success_message += f" API Response: '{response_text}'"
                self.logger.info(success_message)
                return True, success_message
            else:
                # HTTP 오류 발생
                error_message = f"API Error: HTTP {response.status_code}"
                if response_text:
                    error_message += f" - {response_text}"
                self.logger.error(error_message)
                return False, error_message

        except requests.exceptions.RequestException as e:
            self.logger.error(f"{self.NAME.capitalize()} API request failed: {e}")
            return False, f"API Request Error: {e}"