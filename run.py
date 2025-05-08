# /ddns-updater-python-ver-ipv4/run.py
import os
import sys
import logging
import datetime
from datetime import timezone as dt_timezone 
import time 
import pytz 
from threading import Thread 
import signal 

from ddns_updater.app import app 
from ddns_updater.config import read_config, read_global_config, CONFIG_FILE_NAME # CONFIG_FILE_NAME 추가
from ddns_updater.state import load_state, save_state, update_record_state, STATE_FILE_NAME
from ddns_updater.updater import update_single_record 
from ddns_updater.utils import parse_duration, format_timedelta

PROJECT_ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(PROJECT_ROOT_DIR, CONFIG_FILE_NAME)
STATE_FILE = os.path.join(PROJECT_ROOT_DIR, STATE_FILE_NAME)
LOG_DIR_BASE = os.path.join(PROJECT_ROOT_DIR, 'logs')

# --- ★★★ 전역 설정 먼저 읽기 ★★★ ---
global_config_initial = read_global_config(config_file_path=CONFIG_FILE, project_root_dir=PROJECT_ROOT_DIR)
DEBUG_MODE_ENABLED = global_config_initial.get('debug_mode', False)
# ---------------------------------

# --- 기본 로거 설정 (디버그 모드 반영) ---
log_level = logging.DEBUG if DEBUG_MODE_ENABLED else logging.INFO # ★★★ 디버그 모드에 따라 레벨 설정 ★★★
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[logging.StreamHandler(sys.stdout)] 
)
main_logger = logging.getLogger("ddns_updater.main") 
# -----------------------------------------

_record_loggers = {} 

def setup_individual_record_logging(log_dir_base_path: str, 
                                    nick_prefix_from_config: str, 
                                    record_section_name_from_config: str) -> logging.Logger:
    logger_name = f"ddns_updater.record.{record_section_name_from_config}"
    
    # 디버그 모드에 따라 개별 로거 레벨도 설정
    record_log_level = logging.DEBUG if DEBUG_MODE_ENABLED else logging.INFO

    if logger_name in _record_loggers:
        # 이미 로거가 있고 레벨이 다르다면 업데이트
        if _record_loggers[logger_name].level != record_log_level:
            _record_loggers[logger_name].setLevel(record_log_level)
            main_logger.debug(f"Adjusted level for cached logger [{record_section_name_from_config}] to {logging.getLevelName(record_log_level)}")

        today_str_ymd_utc_for_filename = datetime.datetime.now(dt_timezone.utc).strftime("%Y%m%d")
        current_file_handler = None
        for handler in _record_loggers[logger_name].handlers:
            if isinstance(handler, logging.FileHandler):
                current_file_handler = handler
                break
        
        if current_file_handler and \
           not current_file_handler.baseFilename.endswith(f"{record_section_name_from_config}_{today_str_ymd_utc_for_filename}.log"):
            main_logger.info(f"Date changed for logger [{record_section_name_from_config}]. Reconfiguring file handler.")
            del _record_loggers[logger_name] # 캐시에서 제거하여 아래에서 새로 만들도록 함
        else:
            return _record_loggers[logger_name]

    record_logger = logging.getLogger(logger_name)
    
    for handler in record_logger.handlers[:]:
        record_logger.removeHandler(handler)
        handler.close() 

    record_logger.setLevel(record_log_level) # ★★★ 디버그 모드 반영 ★★★
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    try:
        log_dir_for_nick = os.path.join(log_dir_base_path, nick_prefix_from_config)
        os.makedirs(log_dir_for_nick, exist_ok=True)
        
        today_str_ymd_utc = datetime.datetime.now(dt_timezone.utc).strftime("%Y%m%d")
        log_file_path = os.path.join(log_dir_for_nick, f"DDNS_Log_{record_section_name_from_config}_{today_str_ymd_utc}.log")
        
        file_handler = logging.FileHandler(log_file_path, encoding='utf-8')
        file_handler.setFormatter(formatter)
        record_logger.addHandler(file_handler)
        
        record_logger.propagate = False 
        
        main_logger.info(f"File logger setup/reconfigured for [{record_section_name_from_config}] at {log_file_path} with level {logging.getLevelName(record_log_level)}")
        _record_loggers[logger_name] = record_logger
    except Exception as e:
        main_logger.error(f"Error setting up file logger for [{record_section_name_from_config}]: {e}", exc_info=True)
        return main_logger 
        
    return record_logger

# --- run_initial_updates_and_sync_state 함수는 global_config를 이미 사용하므로 큰 변경 없음 ---
def run_initial_updates_and_sync_state():
    main_logger.info("--- Running Initial DDNS Updates and State Sync ---")
    
    # global_config_initial은 이미 위에서 DEBUG_MODE_ENABLED 설정에 사용됨
    global_config = global_config_initial 
    config_records_list = read_config(config_file_path=CONFIG_FILE, project_root_dir=PROJECT_ROOT_DIR)
    # ... (이하 로직은 이전과 거의 동일, global_config 변수명 일치 확인) ...
    nick_prefix = global_config.get('nick', 'default_nick')

    if not config_records_list:
        main_logger.info("No records found in config file. Skipping initial updates.")
        save_state({}, state_file_path=STATE_FILE, project_root_dir=PROJECT_ROOT_DIR)
        return

    main_logger.info("Synchronizing config and state file...")
    current_full_state = load_state(state_file_path=STATE_FILE, project_root_dir=PROJECT_ROOT_DIR)
    new_full_state_for_save = {} 
    state_modified = False

    active_sections_in_config = {rec.get('section_name') for rec in config_records_list if rec.get('section_name')}

    for config_rec_dict in config_records_list:
        section_name = config_rec_dict.get('section_name')
        if not section_name:
            continue

        default_state_template = {
            "status1": "Not configured", "status2": "", "current_ip": "", 
            "previous_ips": [], "date1": "", "date2": "", "time1": "", "time2": "", "status3": "",
            "last_success_update_timestamp_utc": None,
            "last_attempt_timestamp_utc": None
        }
        existing_record_state = current_full_state.get(section_name, default_state_template.copy())
        
        if section_name not in current_full_state:
            main_logger.info(f"New section '{section_name}' found in config. Initializing its state.")
            state_modified = True
        
        new_full_state_for_save[section_name] = existing_record_state

    sections_to_remove_from_state = set(current_full_state.keys()) - active_sections_in_config
    if sections_to_remove_from_state:
        main_logger.info(f"Removing obsolete sections from state: {', '.join(sections_to_remove_from_state)}")
        for section_key in sections_to_remove_from_state:
            if section_key in new_full_state_for_save: 
                 del new_full_state_for_save[section_key]
        state_modified = True

    if state_modified:
        main_logger.info("State file needs update due to config changes. Saving synchronized state...")
        save_success, save_msg = save_state(new_full_state_for_save, state_file_path=STATE_FILE, project_root_dir=PROJECT_ROOT_DIR)
        if not save_success:
            main_logger.error(f"ERROR: Failed to save synchronized state: {save_msg}")

    main_logger.info("State synchronization complete.")
    
    current_full_state = new_full_state_for_save 

    for config_rec_dict in config_records_list:
        section_name = config_rec_dict.get('section_name')
        domain = config_rec_dict.get('domain')
        owner = config_rec_dict.get('owner', '@')
        full_domain_to_log = f"{owner}.{domain}" if owner != '@' else domain

        if not section_name or not domain:
            main_logger.warning(f"Skipping invalid record config (missing section_name or domain): {config_rec_dict}")
            continue

        record_logger = setup_individual_record_logging(LOG_DIR_BASE, nick_prefix, section_name)
        record_logger.info(f"Initial update check starting for record: [{section_name}] ({full_domain_to_log})")
        
        overall_success, result_ip, result_message = False, None, "Initial update not attempted."
        try:
            overall_success, result_ip, result_message = update_single_record(
                logger=record_logger,
                record_config_dict=config_rec_dict,
                global_config_dict=global_config # 전역 설정 전달
            )
        except Exception as e:
            record_logger.exception(f"Unexpected error during initial update for [{section_name}]")
            result_message = f"Internal error during initial update: {e}"

        now_utc_for_state = datetime.datetime.now(dt_timezone.utc)
        state_info_to_save = {
            'status_message': result_message,
            'last_attempt_utc': now_utc_for_state,
            'update_successful': overall_success 
        }
        if overall_success and result_ip: 
            state_info_to_save['current_ip'] = result_ip
            record_logger.info(f"Initial update successful. New IP: {result_ip}. Message: {result_message}")
        elif overall_success: 
            state_info_to_save['current_ip'] = result_ip 
            record_logger.info(f"Initial update check completed. Status: {result_message}")
        else: 
            state_info_to_save['current_ip'] = None 
            record_logger.error(f"Initial update failed: {result_message}")

        record_timezone = config_rec_dict.get('timezone', global_config.get('default_timezone', 'Etc/UTC'))
        state_update_success, state_update_msg = update_record_state(
            section_id=section_name,
            new_info_dict=state_info_to_save,
            record_timezone_str=record_timezone,
            project_root_dir=PROJECT_ROOT_DIR
        )
        if not state_update_success:
            record_logger.critical(f"Failed to save state after initial update for [{section_name}]: {state_update_msg}")
            
    main_logger.info("--- Initial DDNS Updates and State Sync Complete ---")


# --- scheduled_update_loop 함수는 global_config를 이미 사용하므로 큰 변경 없음 ---
def scheduled_update_loop():
    # ... (이전 코드와 거의 동일, global_config 변수명 일치 확인) ...
    main_logger.info("Starting scheduled update loop...")
    
    next_update_times_utc = {}

    global _shutdown_requested 
    while not _shutdown_requested: 
        # 루프 시작 시마다 전역 설정을 다시 읽어 debug_mode 변경 등을 반영
        current_global_config = read_global_config(config_file_path=CONFIG_FILE, project_root_dir=PROJECT_ROOT_DIR)
        # ★★★ 루프 내에서 로깅 레벨 동적 변경 (선택 사항) ★★★
        # new_debug_mode = current_global_config.get('debug_mode', False)
        # current_log_level = logging.DEBUG if new_debug_mode else logging.INFO
        # if main_logger.level != current_log_level:
        #     main_logger.info(f"Adjusting main logger level to {logging.getLevelName(current_log_level)}")
        #     main_logger.setLevel(current_log_level)
        #     # 개별 로거 레벨도 조정 필요 시 setup_individual_record_logging 다시 호출 또는 레벨만 변경
        #     for logger_name_cached in list(_record_loggers.keys()): # list로 복사 후 순회 (삭제 대비)
        #         # setup_individual_record_logging을 다시 호출하면 핸들러가 재설정될 수 있음
        #         # 또는 _record_loggers[logger_name_cached].setLevel(current_log_level) 직접 호출
        #         # 여기서는 setup_individual_record_logging이 레벨을 내부적으로 처리하도록 함
        #         section_from_logger_name = logger_name_cached.split('.')[-1]
        #         setup_individual_record_logging(LOG_DIR_BASE, current_global_config.get('nick'), section_from_logger_name)


        config_records_list = read_config(config_file_path=CONFIG_FILE, project_root_dir=PROJECT_ROOT_DIR)
        
        nick_prefix = current_global_config.get('nick', 'default_nick')
        now_utc = datetime.datetime.now(dt_timezone.utc)

        if not config_records_list:
            main_logger.info("No records configured. Scheduler will sleep for 60 minutes.")
            for _ in range(60 * 60 // 15): 
                if _shutdown_requested: break
                time.sleep(15)
            if _shutdown_requested: break
            continue

        shortest_check_interval_seconds = float('inf') 

        for config_rec_dict in config_records_list:
            if _shutdown_requested: break 

            section_name = config_rec_dict.get('section_name')
            if not section_name:
                continue

            record_logger = setup_individual_record_logging(LOG_DIR_BASE, nick_prefix, section_name)
            
            update_period_seconds = config_rec_dict.get('update_period_seconds', 3600) 
            if update_period_seconds <= 0: 
                record_logger.warning(f"[{section_name}] Invalid update_period ({config_rec_dict.get('update_period')}). Using 1 hour.")
                update_period_seconds = 3600
            
            shortest_check_interval_seconds = min(shortest_check_interval_seconds, update_period_seconds)

            if section_name not in next_update_times_utc:
                current_record_state = load_state(project_root_dir=PROJECT_ROOT_DIR).get(section_name, {})
                last_success_ts = current_record_state.get('last_success_update_timestamp_utc')
                if last_success_ts:
                    next_update_times_utc[section_name] = datetime.datetime.fromtimestamp(last_success_ts, dt_timezone.utc) + \
                                                          datetime.timedelta(seconds=update_period_seconds)
                    record_logger.info(f"[{section_name}] Resuming schedule. Next update based on last success and period.")
                else: 
                    next_update_times_utc[section_name] = now_utc 
                    record_logger.info(f"[{section_name}] Initializing next update time for now (no previous success state).")
            
            if now_utc >= next_update_times_utc.get(section_name, now_utc):
                domain = config_rec_dict.get('domain')
                owner = config_rec_dict.get('owner', '@')
                full_domain_to_log = f"{owner}.{domain}" if owner != '@' else domain
                record_logger.info(f"Scheduled update check for record: [{section_name}] ({full_domain_to_log})")

                current_record_state_for_cooldown = load_state(project_root_dir=PROJECT_ROOT_DIR).get(section_name, {})
                cooldown_seconds = config_rec_dict.get('cooldown_period_seconds', 6 * 3600) 
                last_success_update_timestamp_utc = current_record_state_for_cooldown.get('last_success_update_timestamp_utc')
                
                perform_update = True
                if last_success_update_timestamp_utc:
                    time_since_last_success = now_utc.timestamp() - last_success_update_timestamp_utc
                    if time_since_last_success < cooldown_seconds:
                        remaining_cooldown_td = datetime.timedelta(seconds=int(cooldown_seconds - time_since_last_success))
                        record_logger.info(f"[{section_name}] Cooldown period active. Skipping update for another {format_timedelta(remaining_cooldown_td)}.")
                        perform_update = False
                
                if perform_update:
                    overall_success, result_ip, result_message = False, None, "Scheduled update not attempted."
                    try:
                        overall_success, result_ip, result_message = update_single_record(
                            logger=record_logger,
                            record_config_dict=config_rec_dict,
                            global_config_dict=current_global_config # 현재 루프의 전역 설정 사용
                        )
                    except Exception as e:
                        record_logger.exception(f"Unexpected error during scheduled update for [{section_name}]")
                        result_message = f"Internal error during scheduled update: {e}"

                    now_utc_for_state = datetime.datetime.now(dt_timezone.utc)
                    state_info_to_save = {
                        'status_message': result_message,
                        'last_attempt_utc': now_utc_for_state,
                        'update_successful': overall_success 
                    }
                    if overall_success and result_ip: 
                        state_info_to_save['current_ip'] = result_ip
                        record_logger.info(f"Scheduled update successful. New IP: {result_ip}. Message: {result_message}")
                    elif overall_success: 
                        state_info_to_save['current_ip'] = result_ip
                        record_logger.info(f"Scheduled update check completed. Status: {result_message}")
                    else:
                        state_info_to_save['current_ip'] = None
                        record_logger.error(f"Scheduled update failed: {result_message}")
                    
                    record_timezone_str = config_rec_dict.get('timezone', current_global_config.get('default_timezone', 'Etc/UTC'))
                    state_update_success, state_update_msg = update_record_state(
                        section_id=section_name,
                        new_info_dict=state_info_to_save,
                        record_timezone_str=record_timezone_str,
                        project_root_dir=PROJECT_ROOT_DIR
                    )
                    if not state_update_success:
                         record_logger.critical(f"Failed to save state after scheduled update for [{section_name}]: {state_update_msg}")
                
                next_update_times_utc[section_name] = now_utc + datetime.timedelta(seconds=update_period_seconds)
                try:
                    display_tz = pytz.timezone(config_rec_dict.get('timezone', current_global_config.get('default_timezone')))
                    next_update_display = next_update_times_utc[section_name].astimezone(display_tz).strftime('%Y-%m-%d %H:%M:%S %Z%z')
                except Exception: 
                    next_update_display = next_update_times_utc[section_name].strftime('%Y-%m-%d %H:%M:%S UTC')
                record_logger.info(f"[{section_name}] Next update scheduled at {next_update_display}")
        
        if _shutdown_requested: break 

        sleep_duration_seconds = 15 
        if shortest_check_interval_seconds != float('inf') and shortest_check_interval_seconds > 0:
            candidate_sleep = shortest_check_interval_seconds / 10
            sleep_duration_seconds = min(max(15, candidate_sleep), 300)
        else: 
            sleep_duration_seconds = 600 

        main_logger.debug(f"Scheduler sleeping for {sleep_duration_seconds:.0f} seconds...")
        for _ in range(int(sleep_duration_seconds / 5)): 
            if _shutdown_requested: break
            time.sleep(5)
        if _shutdown_requested: break
        if not _shutdown_requested and sleep_duration_seconds % 5 != 0:
            time.sleep(sleep_duration_seconds % 5)


_shutdown_requested = False
def handle_signal(signum, frame):
    global _shutdown_requested
    signal_name = signal.Signals(signum).name if isinstance(signum, int) and signum in signal.Signals else str(signum)
    if not _shutdown_requested:
        main_logger.info(f"Received signal {signal_name}. Initiating graceful shutdown...")
        _shutdown_requested = True
    else:
        main_logger.warning("Shutdown already in progress. If stuck, manual force quit might be needed.")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    main_logger.info(f"DDNS Updater Application Starting... Debug mode: {DEBUG_MODE_ENABLED}") # 디버그 모드 상태 로깅
    
    try:
        import requests
        import flask
        import pytz
        import configparser 
    except ImportError as e:
        main_logger.critical(f"ERROR: Missing required library: {e.name}. Please install it (e.g., pip install -r requirements.txt).")
        sys.exit(1)

    run_initial_updates_and_sync_state()

    use_flask_ui = os.environ.get("DDNS_UPDATER_NO_UI", "false").lower() != "true"
    flask_thread = None

    if use_flask_ui and not _shutdown_requested: 
        main_logger.info("Starting Flask web server for UI...")
        flask_host = os.environ.get("FLASK_RUN_HOST", "0.0.0.0")
        flask_port = int(os.environ.get("FLASK_RUN_PORT", 40007))
        # Flask 디버그 모드는 설정 파일의 debug_mode 또는 환경 변수로 제어
        flask_debug_env = os.environ.get("FLASK_DEBUG", "").lower()
        if flask_debug_env == "true":
            flask_should_debug = True
        elif flask_debug_env == "false":
            flask_should_debug = False
        else: # 환경 변수 없으면 설정 파일 값 따름
            flask_should_debug = DEBUG_MODE_ENABLED
        
        main_logger.info(f"Flask debug mode: {flask_should_debug}")

        werkzeug_logger = logging.getLogger('werkzeug')
        if not flask_should_debug: 
            werkzeug_logger.setLevel(logging.WARNING)
        else: 
            werkzeug_logger.setLevel(logging.INFO)

        def run_flask():
            try:
                app.run(host=flask_host, port=flask_port, debug=flask_should_debug, use_reloader=False, threaded=True)
            except Exception as e_flask: 
                 main_logger.error(f"Flask server encountered an error: {e_flask}", exc_info=True)
            main_logger.info("Flask server has stopped.")


        flask_thread = Thread(target=run_flask, daemon=True)
        flask_thread.start()
        main_logger.info(f"Flask UI accessible at http://{flask_host}:{flask_port}")
    elif _shutdown_requested:
        main_logger.info("Shutdown requested before Flask UI could start.")
    else:
        main_logger.info("Flask UI is disabled by DDNS_UPDATER_NO_UI environment variable.")

    try:
        if not _shutdown_requested: 
            scheduled_update_loop()
    except (KeyboardInterrupt, SystemExit): 
        if not _shutdown_requested: 
             main_logger.info("DDNS Updater loop interrupted...")
             _shutdown_requested = True 
    except Exception as e:
        main_logger.critical("Critical error in main execution loop. Exiting.", exc_info=True)
    finally:
        main_logger.info("DDNS Updater has stopped.")
        sys.exit(0)