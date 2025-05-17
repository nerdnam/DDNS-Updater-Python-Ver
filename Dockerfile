# Dockerfile

# 1. 기본 이미지 선택 (Python 3.12 슬림 버전 사용 예시)
# 사용하시는 Python 버전에 맞춰 조정하세요.
FROM python:3.12-slim

# 2. 작업 디렉토리 설정
WORKDIR /app

# 3. 환경 변수 설정
#    - PYTHONUNBUFFERED: Python의 출력이 버퍼링 없이 바로 나오도록 설정 (Docker 로그 확인에 유용)
#    - TZ: 컨테이너의 타임존 설정 (로그 시간 등에 영향)
ENV PYTHONUNBUFFERED=1
ENV TZ=Etc/UTC
#    - Flask 실행 관련 환경 변수 기본값 설정
#      docker-compose.yml 또는 docker run -e 옵션으로 오버라이드 가능
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=30007 
#    - Flask Secret Key는 보안상 Dockerfile에 직접 넣는 것보다
#      실행 시 환경 변수로 주입하는 것이 훨씬 안전합니다.
# ENV FLASK_SECRET_KEY="your_default_secret_key_here_if_needed" 
#    - UI 활성화 여부 기본값
ENV DDNS_UPDATER_NO_UI=false

# 4. 시스템 의존성 설치 (필요한 경우)
#    tzdata 패키지는 ENV TZ 설정을 시스템 레벨에서 적용하는 데 도움을 줄 수 있습니다.
# RUN apt-get update && apt-get install -y --no-install-recommends \
#     tzdata \
#  && rm -rf /var/lib/apt/lists/*

# 5. requirements.txt 복사 및 의존성 설치
#    - 먼저 requirements.txt만 복사하여 Docker 레이어 캐시를 활용합니다.
COPY requirements.txt ./
#    - --no-cache-dir 옵션으로 이미지 크기 최적화
RUN pip install --no-cache-dir -r requirements.txt

# 6. 애플리케이션 코드 전체 복사
#    - .dockerignore 파일을 사용하여 불필요한 파일 제외 권장
COPY . .
#    - 또는 필요한 파일/디렉토리만 명시적으로 복사:
# COPY ddns_updater/ ./ddns_updater/
# COPY run.py ./
# COPY templates/ ./templates/
# COPY static/ ./static/
# COPY ddns_config.ini.example ./ddns_config.ini # 기본 설정 파일로 복사 (선택 사항)

# 7. 애플리케이션 포트 노출 (Flask UI용)
#    - ENV FLASK_RUN_PORT 값과 일치시키는 것이 좋음
EXPOSE 30007 

# 8. 데이터 볼륨 설정 (로그 디렉토리)
#    - 설정 파일과 상태 파일은 실행 시 호스트 볼륨으로 마운트하는 것을 권장
VOLUME /app/logs

# 9. 컨테이너 실행 시 실행될 기본 명령어
#    - python run.py를 실행합니다.
CMD ["python", "run.py"]