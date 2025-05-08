# ddns_updater/providers/dnspod_provider.py
import json
import requests
from urllib.parse import urlencode # for x-www-form-urlencoded

from .base_provider import BaseProvider

class DnspodProvider(BaseProvider):
    NAME = "dnspod"
    API_BASE_URL = "https://dnsapi.cn"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.token = self.config.get('dnspod_token') # DNSPod API Token (ID,Token 형식)
        # self.domain, self.owner 는 BaseProvider 에서 처리

        # 필수 설정값 확인
        if not all([self.token, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (dnspod_token, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        
        # owner가 없으면 '@' 또는 DNSPod에서 사용하는 기본값 (예: '@')으로 설정
        if not self.config.get('owner'):
            self.config['owner'] = '@' # 또는 DNSPod API가 기대하는 기본값
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")


    @staticmethod
    def get_required_config_fields():
        # owner는 DNSPod에서 sub_domain으로 사용됨.
        return ["dnspod_token", "domain", "owner"]

    @staticmethod
    def get_optional_config_fields():
        # DNSPod API는 TTL, MX 우선순위 등을 설정할 수 있음.
        # Record.Ddns API는 TTL 파라미터를 지원하지 않는 것으로 보임 (문서 확인 필요).
        # Record.Modify API는 TTL 지원.
        return {"ttl": None} 

    @staticmethod
    def get_description():
        return "Updates DNS records on DNSPod (Tencent Cloud) using their API."

    def _build_common_payload(self):
        """공통 요청 파라미터 (form-urlencoded 용 딕셔너리)"""
        return {
            'login_token': self.token,
            'format': 'json',
            # 'lang': 'en' # 필요시 언어 설정
        }

    def _make_api_request(self, endpoint_path, payload_dict):
        """DNSPod API 요청 실행 (POST, x-www-form-urlencoded)"""
        url = f"{self.API_BASE_URL}{endpoint_path}"
        headers = {
            'User-Agent': f'Python-DDNS-Updater/{self.NAME}',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }
        timeout = self.config.get('http_timeout_seconds', 10)

        # 페이로드를 x-www-form-urlencoded 문자열로 인코딩
        encoded_payload = urlencode(payload_dict)

        try:
            response = requests.post(url, data=encoded_payload, headers=headers, timeout=timeout)
            response.raise_for_status() # HTTP 오류 발생 시 예외 발생
            
            # DNSPod API는 성공 시에도 status.code가 "1"이 아니면 오류일 수 있음.
            # 응답 본문이 비어있는 경우는 거의 없을 것으로 예상.
            response_data = response.json()

            # DNSPod API 응답 공통 구조 확인 (status 객체)
            status = response_data.get('status', {})
            status_code = status.get('code')
            status_message = status.get('message', 'Unknown API status message.')

            if status_code != "1": # "1"이 성공을 의미
                error_msg = f"API Error (DNSPod status code {status_code}): {status_message}"
                self.logger.error(f"DNSPod API call to {endpoint_path} failed. {error_msg}")
                return None, error_msg
            
            return response_data, None # 성공 시 전체 JSON 데이터 반환
            
        except requests.exceptions.HTTPError as e:
            error_body = e.response.text if e.response else "No response body"
            self.logger.error(f"DNSPod API HTTP error: {e.response.status_code if e.response else 'N/A'} - {error_body}")
            # HTTP 오류 시에도 DNSPod 형식의 오류 메시지가 있을 수 있음
            try:
                error_data = json.loads(error_body)
                status = error_data.get('status', {})
                api_code = status.get('code', 'UnknownCode')
                api_message = status.get('message', 'No message in error response')
                return None, f"API HTTP Error: {e.response.status_code if e.response else 'N/A'} (DNSPod Code: {api_code}, Message: {api_message})"
            except (json.JSONDecodeError, TypeError): # TypeError for non-string error_body
                return None, f"API HTTP Error: {e.response.status_code if e.response else 'N/A'} - {error_body}"
        except requests.exceptions.RequestException as e:
            self.logger.error(f"DNSPod API request failed: {e}")
            return None, f"API Request Error: {e}"
        except json.JSONDecodeError as e: # 성공 응답 후 JSON 파싱 실패
            response_text = response.text if 'response' in locals() and hasattr(response, 'text') else 'N/A'
            self.logger.error(f"DNSPod API JSON decode error: {e}. Response: {response_text}")
            return None, f"API JSON Decode Error: {e}"

    def _get_record_info(self, record_type_filter):
        """지정된 타입의 DNS 레코드 ID, 현재 IP, 레코드 라인을 조회 (Go의 Update 함수 1단계)."""
        owner_val = self.config.get('owner', '@')
        self.logger.debug(f"DNSPod: Finding record info for owner '{owner_val}' on domain '{self.domain}' (type: {record_type_filter})")
        
        payload = self._build_common_payload()
        payload.update({
            'domain': self.domain,
            'length': "200", # 충분히 큰 값으로 설정하여 모든 레코드 조회 시도
            'sub_domain': owner_val,
            'record_type': record_type_filter
        })

        data, error_msg = self._make_api_request("/Record.List", payload)
        if error_msg:
            return None, None, None, error_msg # record_id, current_ip, record_line, error_message
        
        if data and 'records' in data:
            records = data.get('records', [])
            for record in records:
                # DNSPod는 sub_domain으로 필터링해도 다른 타입의 레코드가 함께 올 수 있으므로,
                # record.name (owner)과 record.type을 다시 한번 확인.
                if record.get('name') == owner_val and record.get('type') == record_type_filter:
                    record_id = record.get('id')
                    current_ip = record.get('value')
                    record_line = record.get('line', '默认') # 기본 라인 또는 API에서 반환된 라인
                    if record_id:
                        self.logger.info(f"DNSPod: Found RecordId: {record_id} for owner '{owner_val}' with IP: {current_ip}, Line: {record_line}")
                        return record_id, current_ip, record_line, None
            
            # 일치하는 레코드 없음
            self.logger.info(f"DNSPod: No existing record found for owner '{owner_val}' (type: {record_type_filter}).")
            return None, None, None, None # 레코드 없음 (오류는 아님)
        else:
            msg = f"DNSPod: Failed to get record info or unexpected response format from /Record.List. Response: {data}"
            self.logger.error(msg)
            return None, None, None, msg

    def _ddns_update_record(self, record_id, record_line, owner_val, ip_address):
        """DDNS 방식으로 레코드를 업데이트 (Go의 Update 함수 2단계)."""
        self.logger.info(f"DNSPod: Updating RecordId {record_id} (owner '{owner_val}', line '{record_line}') in domain '{self.domain}' to IP {ip_address}")
        
        payload = self._build_common_payload()
        payload.update({
            'domain': self.domain,
            'record_id': record_id,
            'value': ip_address,
            'record_line': record_line, # Record.List에서 가져온 라인 사용
            'sub_domain': owner_val
            # 'ttl': self.config.get('ttl') # Record.Ddns는 TTL 파라미터 미지원으로 보임
        })

        data, error_msg = self._make_api_request("/Record.Ddns", payload)
        if error_msg:
            return False, error_msg # success_boolean, message_string
        
        if data and 'record' in data:
            updated_record = data['record']
            updated_ip = updated_record.get('value')
            if updated_ip == ip_address:
                self.logger.info(f"DNSPod: Successfully updated RecordId {record_id}. New IP confirmed: {updated_ip}")
                return True, f"Successfully updated RecordId {record_id} to IP {ip_address}."
            else:
                msg = f"DNSPod: Successfully updated RecordId {record_id}, but API returned IP '{updated_ip}' instead of '{ip_address}'."
                self.logger.warning(msg)
                return True, msg # 일단 성공으로 처리하나 경고
        else:
            msg = f"DNSPod: Failed to update record via /Record.Ddns or unexpected response format. Response: {data}"
            self.logger.error(msg)
            return False, msg

    def update_record(self, ip_address, record_type="A", proxied=None):
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        owner_val = self.config.get('owner', '@')
        self.logger.info(f"DNSPod: Attempting to update owner '{owner_val}' on domain '{self.domain}' ({record_type}) to IP: {ip_address}")

        record_id, current_ip, record_line, error_msg = self._get_record_info(record_type)
        
        if error_msg:
            return False, error_msg
        
        if not record_id: # 레코드 없음
            # DNSPod는 Record.Create API로 레코드 생성 가능.
            # Go 코드는 레코드 없으면 오류. 여기서는 일단 Go 코드 동작을 따름.
            # 필요하다면 여기에 _create_dns_record 로직 추가.
            msg = f"DNSPod: Record for owner '{owner_val}', type '{record_type}' on domain '{self.domain}' does not exist. Auto-creation not implemented (matching Go client behavior)."
            self.logger.error(msg)
            return False, msg

        if current_ip == ip_address:
            msg = f"DNSPod: IP address {ip_address} for owner '{owner_val}' on domain '{self.domain}' is already up to date."
            self.logger.info(msg)
            return True, msg
        
        # IP가 다르면 DDNS 방식으로 업데이트
        success, msg = self._ddns_update_record(record_id, record_line, owner_val, ip_address)
        return success, msg