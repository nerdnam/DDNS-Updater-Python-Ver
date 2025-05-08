# ddns_updater/providers/gcp_provider.py
import json
import logging # GCP 라이브러리가 자체 로깅을 사용할 수 있으므로, 충돌 방지 위해 명시적 로깅
import requests

# google-auth 라이브러리 필요: pip install google-auth google-auth-httplib2 requests
from google.oauth2 import service_account
from google.auth.transport.requests import AuthorizedSession

from .base_provider import BaseProvider

class GcpProvider(BaseProvider):
    NAME = "gcp"
    API_BASE_URL = "https://dns.googleapis.com/dns/v1"

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.project_id = self.config.get('gcp_project_id')
        self.managed_zone_name = self.config.get('gcp_managed_zone_name')
        credentials_json_str = self.config.get('gcp_credentials_json')
        
        # self.domain, self.owner 는 BaseProvider 에서 처리
        # owner 기본값 설정 (GCP는 FQDN을 사용하므로 owner가 @여도 명시적 처리 필요)
        if not self.config.get('owner'):
            self.config['owner'] = '@'
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")

        # 필수 설정값 확인
        if not all([self.project_id, self.managed_zone_name, credentials_json_str, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (gcp_project_id, gcp_managed_zone_name, gcp_credentials_json, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

        try:
            credentials_info = json.loads(credentials_json_str)
            if not credentials_info.get("type") == "service_account": # 기본적인 서비스 계정 키인지 확인
                 raise ValueError("Credentials JSON must be for a service account and contain a 'type' field.")
            # 필요한 스코프 정의
            scopes = [
                "https://www.googleapis.com/auth/ndev.clouddns.readwrite",
                # "https://www.googleapis.com/auth/cloud-platform" # 더 넓은 스코프, 필요시 사용
            ]
            self.credentials = service_account.Credentials.from_service_account_info(
                credentials_info, scopes=scopes
            )
            # 인증된 세션 생성 (API 요청 시 사용)
            self.authed_session = AuthorizedSession(self.credentials)
            self.authed_session.headers.update({'User-Agent': f'Python-DDNS-Updater/{self.NAME}'})

        except json.JSONDecodeError as e:
            error_msg = f"{self.NAME.capitalize()} provider: Invalid 'gcp_credentials_json' format: {e}"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        except Exception as e: # google-auth 라이브러리에서 발생할 수 있는 다른 예외 처리
            error_msg = f"{self.NAME.capitalize()} provider: Failed to load GCP credentials: {e}"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
            
        # TTL 설정 (GCP는 레코드 세트별 TTL)
        try:
            self.ttl = int(self.config.get('gcp_ttl', 300)) # 기본 TTL 300초
            if self.ttl < 0: # GCP 최소 TTL 확인 필요 (보통 0 또는 양수)
                self.logger.warning(f"{self.NAME.capitalize()}: TTL {self.ttl} is invalid, using 300. Check GCP's minimum TTL.")
                self.ttl = 300
        except ValueError:
            self.logger.warning(f"{self.NAME.capitalize()}: Invalid TTL value '{self.config.get('gcp_ttl')}', using default 300.")
            self.ttl = 300


    @staticmethod
    def get_required_config_fields():
        return [
            "gcp_project_id", 
            "gcp_managed_zone_name", 
            "gcp_credentials_json", # 서비스 계정 키 JSON 문자열
            "domain", 
            "owner"
        ]

    @staticmethod
    def get_optional_config_fields():
        return {"gcp_ttl": 300}

    @staticmethod
    def get_description():
        return "Updates DNS records on Google Cloud DNS using OAuth 2.0 with a Service Account."

    def _build_fqdn(self):
        """API에 사용될 FQDN 구성 (끝에 점 포함)"""
        owner = self.config.get('owner', '@')
        # GCP는 owner가 '@'일 때 FQDN은 domain + '.' 형태.
        # owner가 'www'이면 'www.domain.' 형태.
        if owner == '@' or owner == '' or owner is None:
            return f"{self.domain}."
        return f"{owner}.{self.domain}."

    def _parse_gcp_error(self, response_content_str):
        """GCP API 오류 응답 파싱 (Go의 decodeError 참조)"""
        try:
            error_data_outer = json.loads(response_content_str)
            error_data = error_data_outer.get("error", {})
            messages = []
            if error_data.get("message"):
                messages.append(error_data["message"])
            for err_item in error_data.get("errors", []):
                if err_item.get("message"):
                    messages.append(f"Reason: {err_item.get('reason', 'N/A')}, Message: {err_item['message']}")
            return "; ".join(messages) if messages else response_content_str
        except json.JSONDecodeError:
            return response_content_str # 파싱 실패 시 원본 반환

    def _make_api_request(self, method, endpoint_path, query_params=None, json_payload=None):
        """GCP Cloud DNS API 요청 실행"""
        # 공통 쿼리 파라미터 (Go의 makeAPIURL 참조)
        common_query_params = {
            'alt': 'json',
            'prettyPrint': 'false'
        }
        if query_params:
            common_query_params.update(query_params)
        
        url = f"{self.API_BASE_URL}{endpoint_path}"
        timeout = self.config.get('http_timeout_seconds', 10) # AuthorizedSession은 자체 타임아웃이 없을 수 있음

        try:
            if method.upper() == "GET":
                response = self.authed_session.get(url, params=common_query_params, timeout=timeout)
            elif method.upper() == "POST":
                response = self.authed_session.post(url, params=common_query_params, json=json_payload, timeout=timeout)
            elif method.upper() == "PATCH": # GCP는 PATCH를 사용
                response = self.authed_session.patch(url, params=common_query_params, json=json_payload, timeout=timeout)
            # GCP Cloud DNS는 레코드 삭제/추가를 위해 POST /changes API를 사용하는 것이 일반적.
            # PUT /rrsets/{name}/{type} 도 가능하지만, 모든 값을 대체.
            # 여기서는 Go 코드의 PATCH /rrsets/{name}/{type} 방식을 따름.
            else:
                self.logger.error(f"Unsupported HTTP method for GCP: {method}")
                return None, f"Unsupported HTTP method: {method}"

            # HTTP 오류 발생 시 예외를 발생시키지 않고 상태 코드로 처리 (Go 코드 방식)
            response_content_str = response.text # 오류 파싱을 위해 미리 읽음

            if 200 <= response.status_code < 300:
                if not response_content_str and response.status_code == 204: # No Content
                    return {}, None # 빈 딕셔너리 (성공)
                return response.json(), None
            else: # 오류 발생
                error_details = self._parse_gcp_error(response_content_str)
                error_msg = f"API Error: HTTP {response.status_code} - {error_details}"
                self.logger.error(f"GCP API call to {method} {url} failed. {error_msg}")
                # 특정 상태 코드에 따른 예외 매핑 (Go 코드 참조)
                if response.status_code == 404:
                    return {"error_type": "NotFound"}, error_msg # NotFound 식별자 추가
                return None, error_msg
            
        except requests.exceptions.RequestException as e: # AuthorizedSession도 requests 예외 발생 가능
            self.logger.error(f"GCP API request failed: {e}")
            return None, f"API Request Error: {e}"
        except json.JSONDecodeError as e: # 성공 응답 후 JSON 파싱 실패
            self.logger.error(f"GCP API JSON decode error: {e}. Response: {response_content_str if 'response_content_str' in locals() else 'N/A'}")
            return None, f"API JSON Decode Error: {e}"


    def _get_rrset(self, fqdn, record_type):
        """특정 레코드 세트 조회 (Go의 getRRSet 참조)"""
        self.logger.debug(f"GCP: Getting RRSet for {fqdn} (type: {record_type})")
        endpoint_path = f"/projects/{self.project_id}/managedZones/{self.managed_zone_name}/rrsets/{fqdn}/{record_type}"
        
        data, error_msg = self._make_api_request("GET", endpoint_path)
        
        if data and data.get("error_type") == "NotFound": # _make_api_request에서 404를 이렇게 처리
            self.logger.info(f"GCP: RRSet for {fqdn} (type: {record_type}) not found.")
            return None, None # 레코드 없음 (오류는 아님)
        if error_msg:
            return None, error_msg
        
        # data는 recordResourceSet 형식의 딕셔너리여야 함
        return data, None 

    def _create_rrset(self, fqdn, record_type, ip_address):
        """새 레코드 세트 생성 (Go의 createRRSet 참조) - PATCH 방식으로 대체 가능"""
        # GCP는 POST /rrsets 로 생성하거나, POST /changes 로 변경사항 제출.
        # Go 코드는 POST /rrsets 사용.
        self.logger.info(f"GCP: Creating RRSet for {fqdn} ({record_type}) with IP {ip_address}")
        endpoint_path = f"/projects/{self.project_id}/managedZones/{self.managed_zone_name}/rrsets"
        payload = {
            "name": fqdn,
            "type": record_type,
            "ttl": self.ttl,
            "rrdatas": [ip_address]
        }
        data, error_msg = self._make_api_request("POST", endpoint_path, json_payload=payload)
        if error_msg:
            return False, error_msg
        # 성공 시 data에 생성된 리소스 정보 포함
        return True, "RRSet created successfully (assumed)."


    def _patch_rrset(self, fqdn, record_type, ip_address):
        """기존 레코드 세트 업데이트 (Go의 patchRRSet 참조)"""
        self.logger.info(f"GCP: Patching RRSet for {fqdn} ({record_type}) to IP {ip_address}")
        endpoint_path = f"/projects/{self.project_id}/managedZones/{self.managed_zone_name}/rrsets/{fqdn}/{record_type}"
        payload = {
            # PATCH는 변경할 필드만 포함. name, type은 URL에 있으므로 보통 불필요.
            # 하지만 Go 코드는 name, type을 포함. GCP API가 이를 어떻게 처리하는지 확인 필요.
            # 여기서는 rrdatas와 ttl만 변경한다고 가정.
            "name": fqdn, # Go 코드와 일치시키기 위해 포함
            "type": record_type, # Go 코드와 일치시키기 위해 포함
            "ttl": self.ttl,
            "rrdatas": [ip_address] # 새 IP로 rrdatas 전체를 교체
        }
        data, error_msg = self._make_api_request("PATCH", endpoint_path, json_payload=payload)
        if error_msg:
            return False, error_msg
        return True, "RRSet patched successfully (assumed)."

    def update_record(self, ip_address, record_type="A", proxied=None):
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        fqdn = self._build_fqdn()
        self.logger.info(f"GCP: Attempting to update {fqdn} ({record_type}) to IP: {ip_address}")

        # 1. 기존 레코드 세트 조회
        rrset_data, error_msg = self._get_rrset(fqdn, record_type)
        
        if error_msg: # 조회 중 심각한 오류 발생
            return False, f"Failed to get existing RRSet: {error_msg}"

        if rrset_data is None: # 레코드 없음 (404 등)
            self.logger.info(f"GCP: RRSet for {fqdn} ({record_type}) not found. Creating new one.")
            create_success, create_msg = self._create_rrset(fqdn, record_type, ip_address)
            return create_success, create_msg
        
        # 레코드 존재
        current_ips = rrset_data.get("rrdatas", [])
        if ip_address in current_ips:
            # TTL도 같은지 확인하는 로직 추가 가능 (rrset_data.get("ttl") == self.ttl)
            msg = f"GCP: IP address {ip_address} for {fqdn} is already up to date."
            self.logger.info(msg)
            return True, msg
        
        # IP가 다르거나, TTL 등 다른 속성 변경 필요 시 PATCH
        # (주의: 이 PATCH는 rrdatas를 완전히 대체함. 여러 IP가 있는 레코드의 경우 주의)
        self.logger.info(f"GCP: RRSet for {fqdn} ({record_type}) found with different IP/settings. Patching. Current IPs: {current_ips}")
        patch_success, patch_msg = self._patch_rrset(fqdn, record_type, ip_address)
        return patch_success, patch_msg