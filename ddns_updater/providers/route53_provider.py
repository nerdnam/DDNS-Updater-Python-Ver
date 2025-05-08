# ddns_updater/providers/route53_provider.py
import logging
# boto3 라이브러리 필요: pip install boto3
import boto3
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

from .base_provider import BaseProvider

class Route53Provider(BaseProvider):
    NAME = "route53"
    # boto3가 엔드포인트를 자동으로 처리하므로 API_BASE_URL 불필요

    def __init__(self, config, logger):
        super().__init__(config, logger)
        self.aws_access_key_id = self.config.get('route53_aws_access_key_id')
        self.aws_secret_access_key = self.config.get('route53_aws_secret_access_key')
        self.zone_id = self.config.get('route53_zone_id') # 예: Z1234567890ABCDEFGHI
        
        try:
            # Route 53 TTL은 초 단위, 최소 0 (캐싱 안 함) 또는 1부터 가능 (문서 확인)
            # Go 코드는 기본 300.
            self.ttl = int(self.config.get('route53_ttl', 300)) 
            if self.ttl < 0: # 보통 0 또는 양수
                self.logger.warning(f"{self.NAME.capitalize()}: TTL {self.ttl} is invalid, using 300. Check Route 53's minimum TTL.")
                self.ttl = 300
        except ValueError:
            self.logger.warning(f"{self.NAME.capitalize()}: Invalid TTL value '{self.config.get('route53_ttl')}', using default 300.")
            self.ttl = 300
            
        # self.domain, self.owner 는 BaseProvider 에서 처리
        # owner 기본값 설정
        if not self.config.get('owner'):
            self.config['owner'] = '@' # Route 53은 Name 필드에 FQDN 사용, @는 보통 루트 도메인
            self.logger.debug(f"{self.NAME.capitalize()}: 'owner' not set, defaulting to '@'.")

        # 필수 설정값 확인
        if not all([self.aws_access_key_id, self.aws_secret_access_key, self.zone_id, self.domain]):
            error_msg = f"{self.NAME.capitalize()} provider: Missing required configuration (aws_access_key_id, aws_secret_access_key, zone_id, domain)."
            self.logger.error(error_msg)
            raise ValueError(error_msg)

        try:
            # boto3 클라이언트 초기화
            # 리전은 Route 53의 경우 보통 'us-east-1' (글로벌 서비스)이지만,
            # boto3는 엔드포인트를 자동으로 결정하거나, 명시적으로 지정 가능.
            # Go 코드는 'us-east-1'을 사용.
            self.r53_client = boto3.client(
                'route53',
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                # region_name='us-east-1' # 필요시 명시
            )
        except (NoCredentialsError, PartialCredentialsError) as e:
            error_msg = f"{self.NAME.capitalize()} provider: AWS credentials error: {e}"
            self.logger.error(error_msg)
            raise ValueError(error_msg)
        except Exception as e: # 기타 boto3 초기화 오류
            error_msg = f"{self.NAME.capitalize()} provider: Failed to initialize AWS Route 53 client: {e}"
            self.logger.error(error_msg)
            raise ValueError(error_msg)


    @staticmethod
    def get_required_config_fields():
        # owner는 Route 53에서 레코드 Name 구성에 필요.
        return [
            "route53_aws_access_key_id", 
            "route53_aws_secret_access_key", 
            "route53_zone_id", 
            "domain", 
            "owner"
        ]

    @staticmethod
    def get_optional_config_fields():
        return {"route53_ttl": 300}

    @staticmethod
    def get_description():
        return "Updates DNS records on AWS Route 53 using AWS SDK (boto3)."

    def _build_fqdn_for_api(self):
        """API에 사용될 FQDN 구성 (Route 53은 끝에 점을 자동으로 처리하거나 요구하지 않을 수 있음 - boto3가 처리)"""
        owner = self.config.get('owner', '@')
        if owner == '@' or owner == '' or owner is None:
            return self.domain
        # Route 53은 FQDN을 기대. owner가 @가 아니면 서브도메인.
        return f"{owner}.{self.domain}"

    def update_record(self, ip_address, record_type="A", proxied=None):
        if proxied is not None:
            self.logger.warning(f"{self.NAME.capitalize()} provider does not use the 'proxied' option. It will be ignored.")

        fqdn_to_update = self._build_fqdn_for_api()
        
        self.logger.info(f"{self.NAME.capitalize()}: Attempting to update {fqdn_to_update} ({record_type}) in Zone ID '{self.zone_id}' to IP: {ip_address}")

        # Route 53 API는 'UPSERT' 액션을 사용하여 레코드 생성 또는 업데이트를 한 번에 처리.
        # Go 코드는 UPSERT를 사용.
        change_batch = {
            'Changes': [
                {
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': fqdn_to_update, # boto3는 FQDN 끝에 점을 자동으로 추가/처리할 수 있음
                        'Type': record_type,
                        'TTL': self.ttl,
                        'ResourceRecords': [{'Value': ip_address}]
                    }
                }
            ]
        }
        
        # 주석 추가 가능 (선택 사항)
        # change_batch['Comment'] = f'DDNS update for {fqdn_to_update} to {ip_address} by Python DDNS Updater'

        try:
            response = self.r53_client.change_resource_record_sets(
                HostedZoneId=self.zone_id,
                ChangeBatch=change_batch
            )
            
            self.logger.debug(f"{self.NAME.capitalize()} API Response: {response}")
            
            # 성공 시 응답에는 ChangeInfo (Id, Status, SubmittedAt) 포함.
            # Status가 PENDING이면 변경 사항이 전파 중임을 의미.
            # 이 DDNS 클라이언트의 목적상, API 호출 성공(예외 없음)이면 성공으로 간주.
            change_info = response.get('ChangeInfo', {})
            change_status = change_info.get('Status', 'UNKNOWN')
            change_id = change_info.get('Id', 'N/A')

            if change_status in ['PENDING', 'INSYNC']: # INSYNC는 이미 동기화된 경우 (거의 없음)
                success_message = f"Successfully submitted update for {fqdn_to_update} to IP {ip_address}. Change ID: {change_id}, Status: {change_status}."
                self.logger.info(success_message)
                return True, success_message
            else:
                # 이론적으로 boto3가 오류를 발생시키지만, 만약을 위해
                error_message = f"Update submission to Route 53 for {fqdn_to_update} resulted in unexpected status: {change_status}. Change ID: {change_id}."
                self.logger.error(error_message)
                return False, error_message

        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'UnknownClientError')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            full_error_msg = f"AWS Route 53 API ClientError (Code: {error_code}): {error_message}"
            self.logger.error(full_error_msg)
            # 특정 오류 코드에 따른 처리 가능
            # 예: if error_code == 'InvalidChangeBatch': ...
            return False, full_error_msg
        except Exception as e: # 기타 예외 (네트워크 등)
            self.logger.error(f"{self.NAME.capitalize()} API request failed: {e}")
            return False, f"API Request Error: {e}"