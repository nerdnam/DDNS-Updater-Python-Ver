# /ddns-updater-python-ver-ipv4/ddns_updater/app.py
import os
import datetime
import logging 
import sys 
from flask import Flask, render_template, request, redirect, url_for, flash, get_flashed_messages, jsonify
import pytz 
from datetime import timezone as dt_timezone # alias 추가

from .config import read_config, read_global_config, _get_config_file_path, CONFIG_FILE_NAME
from .state import load_state, update_record_state, _get_state_file_path, STATE_FILE_NAME
from .updater import update_single_record 
from .providers import get_supported_providers
from .ip_fetcher import get_public_ipv4

project_root_abs = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
template_dir_abs = os.path.join(project_root_abs, 'templates')
static_dir_abs = os.path.join(project_root_abs, 'static')

app = Flask(__name__, template_folder=template_dir_abs, static_folder=static_dir_abs)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a_very_secure_default_secret_key_!@#$%^&*()') 

def get_project_paths_for_app():
    config_file = os.path.join(project_root_abs, CONFIG_FILE_NAME)
    state_file = os.path.join(project_root_abs, STATE_FILE_NAME)
    log_dir_base = os.path.join(project_root_abs, 'logs')
    return project_root_abs, config_file, state_file, log_dir_base

def get_flash_message(category):
    messages = get_flashed_messages(category_filter=[category])
    return messages[0] if messages else None

def _get_combined_records_for_display():
    proj_root, conf_file, stat_file, _ = get_project_paths_for_app()
    
    config_records_list = read_config(config_file_path=conf_file, project_root_dir=proj_root)
    current_full_state = load_state(state_file_path=stat_file, project_root_dir=proj_root)
    
    display_records = []

    for config_rec_dict in config_records_list:
        section_name = config_rec_dict.get('section_name')
        if not section_name:
            app.logger.warning(f"Skipping record in config due to missing section_name: {config_rec_dict}")
            continue

        record_specific_state = current_full_state.get(section_name, {})
        
        combined_rec = {
            'id': section_name,
            'domain': config_rec_dict.get('domain', 'N/A'),
            'owner': config_rec_dict.get('owner', '@'),
            'provider': config_rec_dict.get('provider', 'N/A'),
            'ip_version': config_rec_dict.get('ip_version', 'ipv4'),
            'proxied': config_rec_dict.get('proxied', False),
            'status1': record_specific_state.get('status1', 'Not configured'),
            'status2': record_specific_state.get('status2', ''),
            'current_ip': record_specific_state.get('current_ip', ''),
            'previous_ips': record_specific_state.get('previous_ips', []),
            'date1': record_specific_state.get('date1', ''),
            'date2': record_specific_state.get('date2', ''),
            'time1': record_specific_state.get('time1', ''),
            'time2': record_specific_state.get('time2', ''),
            'status3': record_specific_state.get('status3', ''),
            'update_period': config_rec_dict.get('update_period', 'N/A'),
            'cooldown_period': config_rec_dict.get('cooldown_period', 'N/A'),
            'http_timeout': config_rec_dict.get('http_timeout', 'N/A'),
            'timezone': config_rec_dict.get('timezone', 'N/A'),
        }
        display_records.append(combined_rec)
        
    return display_records

@app.route("/")
def index():
    proj_root, conf_file, _, _ = get_project_paths_for_app()
    global_config = read_global_config(config_file_path=conf_file, project_root_dir=proj_root)
    
    combined_records_for_ui = _get_combined_records_for_display()
    try:
        providers_list = get_supported_providers() 
    except Exception as e: 
        app.logger.error(f"Failed to get_supported_providers: {e}", exc_info=True)
        providers_list = []

    log_content_default = "Select a record and run update to see logs, or view individual log files."

    default_timeout = global_config.get('default_http_timeout_seconds', 10)
    current_ipv4 = get_public_ipv4(logger=app.logger, timeout_seconds=default_timeout)
    if current_ipv4 is None:
        current_ipv4 = "Error fetching IP"

    return render_template("index.html",
                           all_records=combined_records_for_ui,
                           providers=providers_list,
                           global_config=global_config,
                           log_content=log_content_default,
                           current_ipv4=current_ipv4,
                           message=get_flash_message('success'),
                           error=get_flash_message('error'),
                           warning=get_flash_message('warning'))

@app.route("/api") 
def api_get_status():
    proj_root, conf_file, stat_file, _ = get_project_paths_for_app()
    
    config_records_list = read_config(config_file_path=conf_file, project_root_dir=proj_root)
    current_full_state = load_state(state_file_path=stat_file, project_root_dir=proj_root)
    
    api_response_dict = {}

    for config_rec_dict in config_records_list:
        section_name = config_rec_dict.get('section_name')
        if not section_name:
            continue

        record_specific_state = current_full_state.get(section_name, {})
        
        api_record_data = {
            'status1': record_specific_state.get('status1', 'Not configured'),
            'status2': record_specific_state.get('status2', ''),
            'current_ip': record_specific_state.get('current_ip', ''),
            'previous_ips': record_specific_state.get('previous_ips', []),
            'date1': record_specific_state.get('date1', ''),
            'date2': record_specific_state.get('date2', ''),
            'time1': record_specific_state.get('time1', ''),
            'time2': record_specific_state.get('time2', ''),
            'status3': record_specific_state.get('status3', ''),
            'id': section_name, 
            'domain': config_rec_dict.get('domain', ''),
            'owner': config_rec_dict.get('owner', '@'),
            'provider': config_rec_dict.get('provider', ''),
            'ip_version': config_rec_dict.get('ip_version', 'ipv4'),
            'proxied': config_rec_dict.get('proxied', False),
        }
        api_response_dict[section_name] = api_record_data
        
    filter_id = request.args.get('id')
    filter_domain = request.args.get('domain')

    if filter_id:
        if filter_id in api_response_dict:
            return jsonify(api_response_dict[filter_id])
        else:
            return jsonify({"error": f"Record with id '{filter_id}' not found"}), 404
    elif filter_domain:
        found_records = {}
        for section, record_data in api_response_dict.items():
            record_fqdn = record_data['domain']
            if record_data['owner'] != '@' and record_data['owner'] != '':
                record_fqdn = f"{record_data['owner']}.{record_data['domain']}"
            
            if record_data['domain'] == filter_domain or record_fqdn == filter_domain:
                found_records[section] = record_data
        
        if found_records:
            if len(found_records) == 1:
                return jsonify(list(found_records.values())[0])
            return jsonify(found_records)
        else:
            return jsonify({"error": f"Record with domain '{filter_domain}' not found"}), 404
    else:
        return jsonify(api_response_dict)

@app.route("/run_update", methods=["POST"])
def run_update():
    proj_root_app, conf_file_app, _, log_dir_base_app = get_project_paths_for_app()
    
    record_section_to_update = request.form.get("record_section")
    if not record_section_to_update:
        flash("No record selected for update.", "error")
        return redirect(url_for('index'))

    global_config = read_global_config(config_file_path=conf_file_app, project_root_dir=proj_root_app)
    all_config_records = read_config(config_file_path=conf_file_app, project_root_dir=proj_root_app)
    
    config_to_update = None
    for record in all_config_records:
        if record.get('section_name') == record_section_to_update:
            config_to_update = record
            break
            
    if not config_to_update:
        flash(f"Configuration for record section '[{record_section_to_update}]' not found.", "error")
        return redirect(url_for('index'))

    domain_to_log = config_to_update.get('domain', 'N/A')
    owner_to_log = config_to_update.get('owner', '@')
    full_domain_to_log = f"{owner_to_log}.{domain_to_log}" if owner_to_log != '@' else domain_to_log
    
    record_specific_logger_name = f"ddns_updater.record.{record_section_to_update}"
    manual_update_logger = logging.getLogger(record_specific_logger_name)
    
    if not manual_update_logger.hasHandlers() or not any(isinstance(h, logging.FileHandler) for h in manual_update_logger.handlers):
        # run.py의 setup_individual_record_logging 함수를 호출하거나 유사 로직 구현
        # 여기서는 app.logger를 사용하고, 파일 로깅은 run.py의 스케줄러가 담당한다고 가정
        # 또는, run.py의 로깅 함수를 app.py에서도 사용할 수 있도록 모듈화 필요
        app.logger.info(f"File logger for '{record_specific_logger_name}' not configured for manual update via UI. Using app logger or existing handlers.")
        if not manual_update_logger.hasHandlers():
             manual_update_logger = app.logger # 핸들러가 아예 없으면 app.logger 사용

    manual_update_logger.info(f"Manual update triggered via UI for record: [{record_section_to_update}] ({full_domain_to_log})")
    
    # update_single_record 호출
    # 반환값: (overall_success, result_ip, result_message)
    overall_success, result_ip, result_message = False, None, "Update not attempted via UI."
    try:
        overall_success, result_ip, result_message = update_single_record(
            logger=manual_update_logger, 
            record_config_dict=config_to_update,
            global_config_dict=global_config
        )
    except Exception as e:
        manual_update_logger.exception(f"Unexpected error during manual DDNS update (UI) for [{record_section_to_update}]")
        result_message = f"Internal error during update: {e}"
        # overall_success는 False로 유지

    # 상태 업데이트를 위한 정보 구성
    now_utc_for_state = datetime.datetime.now(dt_timezone.utc)
    state_info_to_save = {
        'status_message': result_message,
        'last_attempt_utc': now_utc_for_state,
        'update_successful': overall_success # ★★★ update_single_record의 성공 여부 전달 ★★★
    }
    if overall_success and result_ip: # 작업이 성공했고 IP가 반환되었다면
        state_info_to_save['current_ip'] = result_ip
        # last_success_update_timestamp_utc는 update_successful이 True일 때 state.py에서 설정됨
    elif not overall_success: 
        state_info_to_save['current_ip'] = None # 실패 시 IP는 알 수 없음

    flash_category = 'success' if overall_success else 'error'
    if overall_success:
        manual_update_logger.info(f"Manual update (UI) for [{record_section_to_update}] completed. Status: {result_message}")
        if result_ip: # result_ip가 None이 아닐 때 (즉, IP가 성공적으로 설정/확인되었을 때)
             manual_update_logger.info(f"IP for [{record_section_to_update}] (UI): {result_ip}")
    else:
        manual_update_logger.error(f"Manual update (UI) for [{record_section_to_update}] failed: {result_message}")

    record_timezone = config_to_update.get('timezone', global_config.get('default_timezone', 'Etc/UTC'))
    state_update_success, state_update_msg = update_record_state(
        section_id=record_section_to_update, 
        new_info_dict=state_info_to_save,
        record_timezone_str=record_timezone,
        project_root_dir=proj_root_app
    )
    
    if not state_update_success:
        error_msg_state = f"CRITICAL: Failed to save state after manual update (UI) for [{record_section_to_update}]: {state_update_msg}"
        flash(error_msg_state, 'error')
        manual_update_logger.critical(error_msg_state)

    flash(f"Update result for [{record_section_to_update}] ({full_domain_to_log}): {result_message}", flash_category)
    return redirect(url_for('index'))


@app.route("/get_log")
def get_log():
    proj_root_app, conf_file_app, _, log_dir_base_app = get_project_paths_for_app()
    global_config = read_global_config(config_file_path=conf_file_app, project_root_dir=proj_root_app)

    record_section = request.args.get("record_section")
    if not record_section:
        return jsonify({"error": "No record section specified"}), 400

    nick_prefix = global_config.get('nick', 'default_nick')
    log_dir_for_record = os.path.join(log_dir_base_app, nick_prefix)
    
    log_content = f"No logs found for record [{record_section}]."
    log_file_to_read = None

    if os.path.isdir(log_dir_for_record):
        today_str_ymd_utc = datetime.datetime.now(dt_timezone.utc).strftime("%Y%m%d")
        today_log_file = f"DDNS_Log_{record_section}_{today_str_ymd_utc}.log"
        today_log_file_path = os.path.join(log_dir_for_record, today_log_file)

        if os.path.exists(today_log_file_path):
            log_file_to_read = today_log_file_path
            log_content = f"Displaying logs for today ({today_str_ymd_utc} UTC): {os.path.basename(log_file_to_read)}\n\n"
        else:
            try:
                relevant_log_files = [
                    f for f in os.listdir(log_dir_for_record) 
                    if f.startswith(f"DDNS_Log_{record_section}_") and f.endswith(".log")
                ]
                if relevant_log_files:
                    relevant_log_files.sort(reverse=True) 
                    log_file_to_read = os.path.join(log_dir_for_record, relevant_log_files[0])
                    log_content = f"Displaying latest log: {os.path.basename(log_file_to_read)}\n(No log found for today: {today_log_file})\n\n"
            except FileNotFoundError:
                log_content = f"Log directory not found: {log_dir_for_record}"
            except Exception as e:
                log_content = f"Error searching for previous logs: {e}"
    else:
        log_content = f"Log directory for '{nick_prefix}' not found: {log_dir_for_record}"

    if log_file_to_read and os.path.exists(log_file_to_read):
        try:
            with open(log_file_to_read, "r", encoding='utf-8') as f:
                log_lines = f.readlines()
            
            max_lines = 200 
            actual_log_text = "".join(log_lines[-max_lines:])
            
            if len(log_lines) > max_lines:
                log_content = f"(Showing last {max_lines} lines of {os.path.basename(log_file_to_read)})\n" + actual_log_text
            else: 
                if not log_content.endswith("\n\n"): log_content += "\n\n" 
                log_content += actual_log_text
                
        except Exception as e:
            log_content = f"Error reading log file ({os.path.basename(log_file_to_read)}): {e}"
            app.logger.error(f"Error reading log file {log_file_to_read}: {e}", exc_info=True)
            
    return jsonify({"log_content": log_content})