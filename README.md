<p align="center">
<img src="https://raw.githubusercontent.com/nerdnam/DDNS-Updater-Python-Ver/main/favicon/favicon.png"  width="300" height="300" alt="Project Logo">
</p>

<p align="center">
<img src="https://raw.githubusercontent.com/nerdnam/DDNS-Updater-Python-Ver/main/readme/webui.png" alt="Web UI Screenshot">
</p>

---
<p align="center">
<img src="https://raw.githubusercontent.com/nerdnam/DDNS-Updater-Python-Ver/main/readme/homepage_widget.png" alt="Homepage Widget Example">
</p>

<p align="center">
<a href="https://gethomepage.dev/" target="_blank">
  <img src="https://github.com/gethomepage/homepage/raw/main/assets/logo-horizontal-color.svg" width="204" alt="Homepage Logo">
</a>
<br>
<i>Homepage 위젯 연동 예시 (위젯 설정은 아래 참고)</i>
</p>

*   **Homepage 위젯 설정 예시 (`services.yaml`):**
    ```yaml
    - My DDNS Status: # 서비스 그룹명 (원하는 대로 변경)
        - DDNS Updater-py:
            icon: https://raw.githubusercontent.com/nerdnam/DDNS-Updater-Python-Ver/main/favicon/favicon.png # 직접 아이콘 경로 지정
            href: http://YOUR_SERVER_IP:30007 # 실제 접속 주소로 변경
            description: DDNS Updater Status
            widget:
              type: customapi
              url: http://YOUR_SERVER_IP:30007/api?id=YOUR_RECORD_ID # 실제 API 주소 및 레코드 ID로 변경
              refreshInterval: 3600000 # 1시간 (밀리초 단위, 선택 사항, 기본값 10초)
              method: GET # 선택 사항
              mappings:
                - field: domain
                  label: Domain
                - field: provider
                  label: Provider
                - field: current_ip
                  label: IPv4
                - field: status3 # UI의 "Up Status"에 해당 (예: "05-17 18:30")
                  label: Last Update
    ```
    *   `YOUR_SERVER_IP`: DDNS Updater가 실행 중인 서버의 IP 주소 또는 도메인으로 변경하세요.
    *   `YOUR_RECORD_ID`: `ddns_config.ini`에 설정한 특정 레코드의 ID (섹션 이름)로 변경하세요.

---

# DDNS Updater (Python Version - IPv4 Only)

**이 프로젝트는 [qdm12/ddns-updater](https://github.com/qdm12/ddns-updater) 프로젝트를 Python으로 포팅한 버전입니다. 원본 프로젝트의 강력한 DDNS 업데이트 기능은 유지하면서, 현재 상태를 조회할 수 있는 HTTP API 기능을 추가하고 IPv4 전용으로 단순화하는 것을 목표로 합니다.**

Python으로 작성된 동적 DNS(DDNS) 업데이트 클라이언트입니다. 현재 IP 주소를 주기적으로 확인하여, 변경되었을 경우 설정된 DNS 프로바이더의 레코드를 자동으로 업데이트합니다. 웹 UI를 통해 현재 상태 확인 및 수동 업데이트가 가능하며, **추가된 API를 통해 상태 정보를 JSON 형식으로 조회할 수 있습니다.**

현재 버전은 **IPv4 주소 업데이트에만 집중**되어 있으며, IPv6 지원은 추후 계획되어 있습니다.

## 주요 기능

*   **다양한 DDNS 프로바이더 지원**: Cloudflare, GoDaddy, Namecheap 등 다수의 프로바이더 지원 (플러그인 방식으로 확장 가능).
*   **자동 IP 변경 감지 및 업데이트**: 주기적으로 공인 IP 주소를 확인하고 변경 시 DDNS 레코드 업데이트.
*   **레코드별 상세 설정**: 각 DDNS 레코드마다 업데이트 주기, cooldown 시간, 타임존, HTTP 타임아웃 등을 개별적으로 설정 가능.
*   **웹 UI 제공**:
    *   설정된 모든 DDNS 레코드의 현재 상태 (업데이트 여부, 현재 IP, 마지막 업데이트 시간 등) 표시.
    *   개별 레코드 수동 업데이트 기능.
    *   레코드별 로그 조회 기능.
*   **상태 조회 API 제공 (주요 추가 기능)**: 현재 DDNS 레코드 상태 정보를 JSON 형식으로 조회할 수 있는 HTTP API 엔드포인트 제공.
*   **상세 로깅**: 각 레코드별 업데이트 시도 및 결과를 날짜별 로그 파일로 기록.
*   **Docker 지원**: Docker 및 Docker Compose를 사용하여 쉽게 배포 및 실행 가능 (GHCR 이미지 제공).
*   **설정 파일 기반 운영**: `ddns_config.ini` 파일을 통해 모든 설정 관리.
*   **디버그 모드**: 설정 파일을 통해 애플리케이션 전체의 디버그 로깅 및 Flask 디버그 모드 활성화 가능.

## 프로젝트 구조

```
ddns-updater-python-ver/
├── ddns_updater/                           # 메인 애플리케이션 Python 패키지
│   ├── __init__.py                         # ddns_updater 패키지 초기화 파일
│   ├── app.py                              # Flask 웹 애플리케이션 로직 (UI 및 API 라우트)
│   ├── config.py                           # ddns_config.ini 파일 파싱 및 설정 관리 로직
│   ├── ip_fetcher.py                       # 공인 IP 주소 조회 로직
│   ├── state.py                            # ddns_state.json 파일 관리 및 상태 업데이트 로직
│   ├── updater.py                          # 개별 DDNS 레코드 업데이트 처리 로직
│   ├── utils.py                            # 공통 유틸리티 함수 (예: 시간 파싱)
│   └── providers/                          # DDNS 프로바이더별 로직 구현 디렉토리 (플러그인 방식)
│       ├── __init__.py                     # 프로바이더 모듈 동적 로딩 및 관리
│       ├── base_provider.py                # 모든 프로바이더 클래스의 추상 기본 클래스
│       ├── cloudflare_provider.py          # (예: cloudflare_provider.py)
│       ├─  example_provider.py             # (예시) 특정 프로바이더 구현 파일
│       └── ...                             # (기타 모든 프로바이더 파일)
├── logs/                                   # (자동 생성) 로그 파일 저장 디렉토리
│   └── <nick>/                             # 설정 파일의 'nick' 값에 따른 하위 디렉토리
│       └── DDNS_Log_<section>_<date>.log   # 레코드별, 날짜별 로그 파일
├── static/                                 # 웹 UI용 정적 파일 디렉토리 (favicon 등)
│   └── styles.css                          # 웹 UI 스타일시트
├── templates/                              # 웹 UI용 HTML 템플릿 디렉토리
│   └── index.html                          # 메인 웹 페이지 템플릿
├── .github/                                # GitHub Actions 워크플로우
│   └── workflows/
│       └── ghcr-publish.yml                # GHCR 이미지 빌드 및 푸시 자동화
├── .dockerignore                           # Docker 이미지 빌드 시 제외할 파일 목록
├── ddns_config.ini                         # (사용자 생성) 실제 DDNS 설정 파일
├── ddns_config.ini_total_providers         # (예시 파일) 지원하는 모든 프로바이더 설정 예시 포함
├── ddns_state.json                         # (자동 생성) DDNS 레코드의 현재 상태 저장 파일
├── docker-compose.yml                      # Docker Compose 실행을 위한 설정 파일
├── Dockerfile                              # Docker 이미지 생성을 위한 설정 파일
├── LICENSE                                 # 프로젝트 라이선스 파일
├── README.md                               # 이 파일
├── requirements.txt                        # Python 의존성 패키지 목록
└── run.py                                  # 애플리케이션 실행 스크립트 (스케줄러 및 Flask 서버 실행)
```

## 설치 및 실행

이 애플리케이션은 Docker 이미지를 통해 쉽게 실행할 수 있습니다. 또는 소스 코드를 직접 실행할 수도 있습니다.

### 방법 1: Docker 이미지 사용 (권장)

GitHub Container Registry (GHCR)에 미리 빌드된 Docker 이미지를 사용하여 간편하게 실행할 수 있습니다.

**이미지 Pull (선택 사항, `docker run` 또는 `docker-compose up` 시 자동으로 받아옴):**
```bash
docker pull ghcr.io/nerdnam/ddns-updater-python-ver:latest
# 특정 버전을 사용하려면 (예: 0.0.1 버전):
# docker pull ghcr.io/nerdnam/ddns-updater-python-ver:0.0.1
```

#### 1.1 Docker Run을 사용한 실행

```bash
# 호스트에 설정 및 데이터 저장을 위한 디렉토리 생성 (최초 1회)
# 이 스크립트가 있는 위치를 기준으로 ./config 와 ./data 디렉토리를 생성합니다.
mkdir -p ./config
mkdir -p ./data

# 예제 설정 파일을 ./config/ddns_config.ini 로 복사 후, 내용을 자신의 환경에 맞게 수정합니다.
# cp ddns_config.ini_total_providers ./config/ddns_config.ini
# nano ./config/ddns_config.ini # 또는 선호하는 편집기 사용

docker run -d \
  --name ddns-updater-py \
  -p 30007:30007 \
  -v "$(pwd)/config/ddns_config.ini:/app/ddns_config.ini:ro" \
  -v "$(pwd)/data/ddns_state.json:/app/ddns_state.json" \
  -v "$(pwd)/data/logs:/app/logs" \
  -e PYTHONUNBUFFERED=1 \
  -e TZ="Asia/Seoul" \
  -e FLASK_RUN_HOST="0.0.0.0" \
  -e FLASK_RUN_PORT="30007" \
  -e FLASK_SECRET_KEY="your_very_strong_production_secret_key_!@#$%^&*()" \
  ghcr.io/nerdnam/ddns-updater-python-ver:latest
```
*   `-v "$(pwd)/config/ddns_config.ini..."`: 호스트의 설정 파일을 컨테이너로 읽기 전용(`:ro`)으로 마운트합니다. **반드시 실제 경로로 수정하고, `ddns_config.ini` 파일을 준비해야 합니다.**
*   `-v "$(pwd)/data/..."`: 상태 파일과 로그를 호스트에 저장하기 위해 마운트합니다.
*   `-e FLASK_SECRET_KEY=...`: **반드시 강력하고 예측 불가능한 값으로 변경하세요.** 보안상 매우 중요합니다.
*   `ghcr.io/nerdnam/ddns-updater-python-ver:latest`: 사용할 Docker 이미지입니다. 특정 버전을 사용하려면 태그를 변경하세요 (예: `:0.0.1`).

#### 1.2 Docker Compose를 사용한 실행

프로젝트 루트 또는 원하는 위치에 다음 내용으로 `docker-compose.yml` 파일을 생성합니다.

```yaml
# docker-compose.yml
version: '3.8'

services:
  ddns-updater-py: # 서비스 이름 (원하는 대로 변경 가능)
    image: ghcr.io/nerdnam/ddns-updater-python-ver:latest
    # 특정 버전을 사용하려면: image: ghcr.io/nerdnam/ddns-updater-python-ver:0.0.1
    # --- 또는 로컬 Dockerfile을 사용하여 직접 빌드할 경우 (위 image 라인 주석 처리 또는 삭제) ---
    # build:
    #   context: . # Dockerfile이 있는 현재 디렉토리
    #   dockerfile: Dockerfile
    # -----------------------------------------------------------------------------
    container_name: ddns-updater-py # 실행될 컨테이너의 이름
    ports:
      - "30007:30007" # <호스트_포트>:<컨테이너_포트>
    volumes:
      # 호스트에 config 디렉토리를 만들고 그 안에 ddns_config.ini 파일을 위치시키세요.
      # docker-compose.yml 파일이 있는 위치를 기준으로 상대 경로를 사용합니다.
      - ./config/ddns_config.ini:/app/ddns_config.ini:ro
      # 호스트에 data 디렉토리를 만들고 상태 파일과 로그를 저장합니다.
      - ./data/ddns_state.json:/app/ddns_state.json # 초기 실행 시 파일이 없다면 빈 파일로 생성될 수 있음
      - ./data/logs:/app/logs
    environment:
      - PYTHONUNBUFFERED=1
      - TZ=Asia/Seoul # 컨테이너 타임존 설정 (예: Asia/Seoul, Etc/UTC)
      - FLASK_RUN_HOST=0.0.0.0
      - FLASK_RUN_PORT=30007 # Dockerfile 및 run.py와 일치
      # 중요: 실제 운영 시에는 강력하고 예측 불가능한 시크릿 키를 사용하고,
      # .env 파일을 통해 주입하거나 Docker secrets 기능을 사용하는 것이 더 안전합니다.
      - FLASK_SECRET_KEY=your_very_strong_production_secret_key_!@#$%^&*()
      # - DDNS_UPDATER_NO_UI=false # true로 설정 시 UI 비활성화 (기본값 false, 즉 UI 실행)
    restart: unless-stopped # 컨테이너 비정상 종료 시 자동 재시작 (수동 중지 시 제외)
```

**실행 전 준비 (Docker Compose 사용 시):**

*   `docker-compose.yml` 파일이 있는 디렉토리 기준으로 `./config/` 디렉토리를 만들고, 그 안에 `ddns_config.ini` 파일을 준비합니다. (예제: `cp ddns_config.ini_total_providers ./config/ddns_config.ini` 후 수정)
*   `./data/` 디렉토리를 만듭니다 (상태 파일 및 로그 저장용).

**Docker Compose 실행:**

```bash
docker-compose up -d
# 이미지를 다시 빌드해야 하는 경우 (build 섹션 사용 시):
# docker-compose up -d --build
```

**로그 확인:**

```bash
docker-compose logs -f ddns-updater-py
# 또는 docker logs -f ddns-updater-py (docker run 사용 시)
```

**중지 및 제거:**

```bash
docker-compose down
# 또는 docker stop ddns-updater-py && docker rm ddns-updater-py (docker run 사용 시)
```

---

### 방법 2: 소스 코드 직접 실행 (개발 및 테스트용)

#### 사전 준비 사항
*   Python 3.9 이상 권장
*   `pip` (Python 패키지 설치 도구)

#### 2.1 소스 코드 다운로드 또는 클론
```bash
git clone https://github.com/nerdnam/DDNS-Updater-Python-Ver.git
cd DDNS-Updater-Python-Ver
```

#### 2.2 가상 환경 생성 및 활성화 (권장)
```bash
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate.bat  # Windows (cmd)
# .venv\Scripts\activate.ps1 # Windows (PowerShell) - 실행 정책 문제 시: Set-ExecutionPolicy RemoteSigned -Scope Process
```

#### 2.3 의존성 패키지 설치
```bash
pip install -r requirements.txt
```

#### 2.4 설정 파일 준비
프로젝트 루트 디렉토리에 `ddns_config.ini` 파일을 생성하고 설정을 입력합니다. (자세한 설정 예시는 `ddns_config.ini_total_providers` 파일 참고)
```bash
cp ddns_config.ini_total_providers ddns_config.ini
# nano ddns_config.ini # 또는 선호하는 편집기로 수정
```

#### 2.5 애플리케이션 실행
가상 환경이 활성화된 상태에서 다음 명령을 실행합니다:
```bash
python run.py
```
웹 UI는 기본적으로 `http://0.0.0.0:30007` (또는 `http://localhost:30007`)에서 접근 가능합니다.

---

## 웹 UI

애플리케이션 실행 후, 웹 브라우저에서 `http://<서버_IP_또는_localhost>:30007`로 접속하면 다음 기능을 사용할 수 있습니다:

*   **설정된 DDNS 레코드 목록**: 각 레코드의 ID, 도메인, 호스트, 프로바이더, IP 버전, 현재 상태, 마지막 업데이트 시간, 현재 IP, 이전 IP 목록을 보여줍니다.
*   **수동 업데이트**: 각 레코드 옆의 "Update Now" 버튼을 클릭하여 즉시 업데이트를 시도할 수 있습니다.
*   **로그 조회**: 드롭다운 메뉴에서 레코드를 선택하고 "Fetch Log" 버튼을 클릭하여 해당 레코드의 최신 로그를 확인할 수 있습니다.
*   **전역 설정 표시**: `ddns_config.ini`의 `[ddns]` 섹션에 설정된 기본값들을 보여줍니다.
*   **API 사용 가이드**: JSON 형식으로 상태 정보를 조회할 수 있는 API 엔드포인트 사용법을 안내합니다.
*   **현재 감지된 공인 IP**: 웹 UI를 로드할 때 서버가 감지한 공인 IPv4 주소를 표시합니다.

## API 사용법

현재 DDNS 상태 정보를 JSON 형식으로 조회할 수 있습니다.

*   **기본 엔드포인트**: `http://<서버_IP_또는_localhost>:30007/api`
*   **HTTP 메소드**: `GET`

**사용 가능한 경로:**

*   `/api`: 설정된 모든 DDNS 레코드의 상태 정보를 딕셔너리 형태로 반환합니다 (키: 레코드 ID).
*   `/api?id=<레코드_ID>`: 특정 레코드 ID에 해당하는 상태 정보를 반환합니다.
    *   예: `/api?id=home_server`
*   `/api?domain=<도메인_이름>`: 특정 도메인 이름(FQDN 또는 기본 도메인)에 해당하는 레코드(들)의 상태 정보를 반환합니다.
    *   예: `/api?domain=example.com` 또는 `/api?domain=myhost.example.com`

**응답 JSON 예시 (단일 레코드):**
```json
{
  "id": "home_server",
  "domain": "example.com",
  "owner": "@",
  "provider": "cloudflare",
  "ip_version": "ipv4",
  "proxied": false,
  "status1": "Updated",
  "status2": "25-05-07 20:30",
  "status3": "05-07 20:30",
  "current_ip": "123.123.123.123",
  "previous_ips": ["123.123.123.123", "123.123.123.122"],
  "date1": "2025-05-07",
  "date2": "25-05-07",
  "time1": "20:30:00",
  "time2": "20:30"
}
```

## 지원되는 프로바이더

현재 구현된 프로바이더 목록은 `ddns_updater/providers/` 디렉토리 및 `ddns_updater/providers/__init__.py` 파일의 `get_supported_providers()` 함수를 통해 확인할 수 있습니다. 새로운 프로바이더는 `BaseProvider`를 상속하여 쉽게 추가할 수 있습니다.

(아래 목록은 `ddns_config.ini_total_providers` 파일에 명시된 프로바이더를 기준으로 작성되었으며, 실제 구현 여부는 코드 확인이 필요합니다.)
*   Aliyun
*   All-Inkl
*   AWS Route 53
*   ChangeIP
*   Cloudflare
*   Custom URL (HTTP API 방식)
*   DD24
*   DDNSS.de
*   deSEC.io
*   DigitalOcean
*   DNS-O-Matic
*   Domeneshop
*   DonDominio
*   DreamHost
*   DuckDNS
*   Dyn.com
*   Dynu
*   DynV6
*   EasyDNS
*   FreeDNS (afraid.org)
*   Gandi
*   GCP (Google Cloud DNS)
*   GoDaddy
*   GoIP (하드웨어 장비)
*   HE.net (Hurricane Electric)
*   Hetzner DNS
*   Infomaniak
*   INWX
*   Ionos (1&1)
*   Linode
*   LuaDNS
*   MyAddr.tools
*   Name.com
*   Namecheap
*   NameSilo
*   Netcup
*   Njalla
*   No-IP
*   Now-DNS.com
*   OpenDNS
*   OVH (DynHost 및 ZoneDNS API 모드)
*   Porkbun
*   Selfhost.de
*   Servercow.de
*   Spdyn
*   Strato
*   Variomedia.de
*   Vultr
*   ZoneEdit
*   (Example Provider Template - 개발자용 예시)

## 기여

버그 리포트, 기능 제안, 코드 기여 모두 환영합니다. GitHub 저장소를 통해 이슈를 생성하거나 풀 리퀘스트를 보내주세요.

## 라이선스

[MIT 라이선스](LICENSE)
