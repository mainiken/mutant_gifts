import glob
import asyncio
import argparse
import os
import subprocess
import signal
from copy import deepcopy
from random import uniform
from colorama import init, Fore, Style
import shutil
from typing import Optional

from bot.utils.universal_telegram_client import UniversalTelegramClient
from bot.utils.web import run_web_and_tunnel, stop_web_and_tunnel
from bot.config import settings
from bot.core.agents import generate_random_user_agent
from bot.utils import logger, config_utils, proxy_utils, CONFIG_PATH, SESSIONS_PATH, PROXIES_PATH
from bot.core.tapper import run_tapper
from bot.core.registrator import register_sessions
from bot.utils.updater import UpdateManager
from bot.exceptions import InvalidSession, ServerUnavailableError
from bot.utils.session_backup import SessionBackupManager

from telethon.errors import (
    AuthKeyUnregisteredError, AuthKeyDuplicatedError, AuthKeyError,
    SessionPasswordNeededError
)

from pyrogram.errors import (
    AuthKeyUnregistered as PyrogramAuthKeyUnregisteredError,
    SessionPasswordNeeded as PyrogramSessionPasswordNeededError,
    SessionRevoked as PyrogramSessionRevoked
)

init()
shutdown_event = asyncio.Event()

def signal_handler(signum: int, frame) -> None:
    shutdown_event.set()

START_TEXT = f"""
{Fore.RED}ВНИМАНИЕ: Эта ферма не предназначена для продажи!{Style.RESET_ALL}
{Fore.RED}WARNING: This farm is not for sale!{Style.RESET_ALL}
{Fore.RED}¡ADVERTENCIA: ¡Esta granja no está a la venta!{Style.RESET_ALL}
{Fore.RED}ATTENTION: Cette ferme n'est pas à vendre!{Style.RESET_ALL}
{Fore.RED}ACHTUNG: Diese Farm ist nicht zum Verkauf bestimmt!{Style.RESET_ALL}
{Fore.RED}ATTENZIONE: Questa fattoria non è in vendita!{Style.RESET_ALL}
{Fore.RED}注意：この農場は販売用ではありません！{Style.RESET_ALL}
{Fore.RED}주의: 이 농장은 판매용이 아닙니다!{Style.RESET_ALL}
{Fore.RED}注意：此农场不用于销售！{Style.RESET_ALL}
{Fore.RED}ATENÇÃO: Esta fazenda não se destina à venda!{Style.RESET_ALL}

{Fore.LIGHTMAGENTA_EX} 

█▀▄▀█   ▄     ▄▄▄▄▀ ██      ▄     ▄▄▄▄▀       ▄▀  ▄█ ▄████     ▄▄▄▄▀ 
█ █ █    █ ▀▀▀ █    █ █      █ ▀▀▀ █        ▄▀    ██ █▀   ▀ ▀▀▀ █    
█ ▄ █ █   █    █    █▄▄█ ██   █    █        █ ▀▄  ██ █▀▀        █    
█   █ █   █   █     █  █ █ █  █   █         █   █ ▐█ █         █     
   █  █▄ ▄█  ▀         █ █  █ █  ▀           ███   ▐  █       ▀      
  ▀    ▀▀▀            █  █   ██                        ▀             
                     ▀                                                
                                                      

{Style.RESET_ALL}
{Fore.CYAN}Select action:{Style.RESET_ALL}

    {Fore.GREEN}1. Launch clicker{Style.RESET_ALL}
    {Fore.GREEN}2. Create session{Style.RESET_ALL}
    {Fore.GREEN}3. Create session via QR{Style.RESET_ALL}
    {Fore.GREEN}4. Upload sessions via web (BETA){Style.RESET_ALL}

{Fore.CYAN}Developed by: @mainiken{Style.RESET_ALL}
{Fore.CYAN}Our Telegram channel: {Fore.BLUE}https://t.me/+x8gutImPtaQyN2Ey{Style.RESET_ALL}
"""

API_ID = settings.API_ID
API_HASH = settings.API_HASH

def prompt_user_action() -> int:
    logger.info(START_TEXT)
    while True:
        action = input("> ").strip()
        if action.isdigit() and action in ("1", "2", "3", "4"):
            return int(action)
        logger.warning("Invalid action. Please enter a number between 1 and 4.")

async def process() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--action", type=int, help="Action to perform")
    parser.add_argument("--update-restart", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if not settings.USE_PROXY:
        logger.info(f"Detected {len(get_sessions(SESSIONS_PATH))} sessions | USE_PROXY=False")
    else:
        logger.info(f"Detected {len(get_sessions(SESSIONS_PATH))} sessions | "
                    f"{len(proxy_utils.get_proxies(PROXIES_PATH))} proxies")

    action = args.action
    if not action and not args.update_restart:
        action = prompt_user_action()

    if action == 1:
        if not API_ID or not API_HASH:
            raise ValueError("API_ID and API_HASH not found in the .env file.")
        await run_tasks()
    elif action == 2:
        await register_sessions()
    elif action == 3:
        session_name = input("Enter the session name for QR code authentication: ")
        print("Initializing QR code authentication...")
        subprocess.run(["python", "-m", "bot.utils.loginQR", "-s", session_name])
        print("QR code authentication was successful!")
    elif action == 4:
        logger.info("Starting web interface for uploading sessions...")
        signal.signal(signal.SIGINT, signal_handler)
        try:
            web_task = asyncio.create_task(run_web_and_tunnel())
            await shutdown_event.wait()
        finally:
            web_task.cancel()
            await stop_web_and_tunnel()
            print("Program terminated.")

async def move_invalid_session_to_error_folder(session_name: str) -> None:
    if not settings.MOVE_INVALID_SESSIONS_TO_ERROR:
        logger.info(f"Перемещение недействительных сессий отключено в конфиге. Сессия {session_name} не будет перемещена.")
        return
    
    error_dir = os.path.join(SESSIONS_PATH, "error")
    os.makedirs(error_dir, exist_ok=True)
    
    session_patterns = [
        f"{SESSIONS_PATH}/{session_name}.session",
        f"{SESSIONS_PATH}/telethon/{session_name}.session",
        f"{SESSIONS_PATH}/pyrogram/{session_name}.session"
    ]
    
    found = False
    for pattern in session_patterns:
        matching_files = glob.glob(pattern)
        for session_file in matching_files:
            found = True
            if os.path.exists(session_file):
                relative_path = os.path.relpath(os.path.dirname(session_file), SESSIONS_PATH)
                if relative_path == ".":
                    target_dir = error_dir
                else:
                    target_dir = os.path.join(error_dir, relative_path)
                    os.makedirs(target_dir, exist_ok=True)
                
                target_path = os.path.join(target_dir, os.path.basename(session_file))
                try:
                    shutil.move(session_file, target_path)
                    logger.warning(f"Session {session_name} moved to {target_path} due to invalidity")
                except Exception as e:
                    logger.error(f"Error moving session {session_name}: {e}")
    
    if not found:
        logger.error(f"Session {session_name} not found when attempting to move to error folder")

def get_sessions(sessions_folder: str) -> list[str]:
    session_names = glob.glob(f"{sessions_folder}/*.session")
    session_names += glob.glob(f"{sessions_folder}/telethon/*.session")
    session_names += glob.glob(f"{sessions_folder}/pyrogram/*.session")
    return [file.replace('.session', '') for file in sorted(session_names)]

async def get_tg_clients() -> list[UniversalTelegramClient]:
    session_paths = get_sessions(SESSIONS_PATH)

    if not session_paths:
        raise FileNotFoundError("Session files not found")
    
    tg_clients = []
    for session in session_paths:
        session_name = os.path.basename(session)

        if session_name in settings.blacklisted_sessions:
            logger.warning(f"{session_name} | Session is blacklisted | Skipping")
            continue

        accounts_config = config_utils.read_config_file(CONFIG_PATH)
        session_config: dict = deepcopy(accounts_config.get(session_name, {}))
        if 'api' not in session_config:
            session_config['api'] = {}
        api_config = session_config.get('api', {})
        api = None
        if api_config.get('api_id') in [4, 6, 2040, 10840, 21724]:
            api = config_utils.get_api(api_config)

        if api:
            client_params = {
                "session": session,
                "api": api
            }
        else:
            client_params = {
                "api_id": api_config.get("api_id", API_ID),
                "api_hash": api_config.get("api_hash", API_HASH),
                "session": session,
                "lang_code": api_config.get("lang_code", "en"),
                "system_lang_code": api_config.get("system_lang_code", "en-US")
            }

            for key in ("device_model", "system_version", "app_version"):
                if api_config.get(key):
                    client_params[key] = api_config[key]

        session_config['user_agent'] = session_config.get('user_agent', generate_random_user_agent())
        api_config.update(api_id=client_params.get('api_id') or client_params.get('api').api_id,
                          api_hash=client_params.get('api_hash') or client_params.get('api').api_hash)

        session_proxy = session_config.get('proxy')
        if not session_proxy and 'proxy' in session_config.keys():
            max_init_attempts = 2 if settings.AUTO_RESTORE_INVALID_SESSIONS else 1
            
            for attempt in range(max_init_attempts):
                try:
                    tg_clients.append(UniversalTelegramClient(**client_params))
                    if accounts_config.get(session_name) != session_config:
                        await config_utils.update_session_config_in_file(session_name, session_config, CONFIG_PATH)
                    break
                except (AuthKeyUnregisteredError, AuthKeyDuplicatedError, AuthKeyError,
                       SessionPasswordNeededError, PyrogramAuthKeyUnregisteredError,
                        PyrogramSessionPasswordNeededError,
                       PyrogramSessionRevoked, InvalidSession) as e:
                    logger.error(f"{session_name} | Session initialization error: {e}")
                    
                    if attempt < max_init_attempts - 1 and settings.AUTO_RESTORE_INVALID_SESSIONS:
                        backup_manager = SessionBackupManager(SESSIONS_PATH)
                        if backup_manager.backup_exists(session_name):
                            logger.info(f"🔄 {session_name} | Попытка восстановления из бэкапа...")
                            if backup_manager.restore_from_backup(session_name):
                                logger.info(f"✅ {session_name} | Сессия восстановлена, повторная инициализация...")
                                await asyncio.sleep(1)
                                continue
                            else:
                                logger.error(f"❌ {session_name} | Не удалось восстановить из бэкапа")
                        else:
                            logger.warning(f"⚠️ {session_name} | Бэкап не найден")
                    
                    await move_invalid_session_to_error_folder(session_name)
                    break
            continue

        else:
            if settings.DISABLE_PROXY_REPLACE:
                proxy = session_proxy or next(iter(proxy_utils.get_unused_proxies(accounts_config, PROXIES_PATH)), None)
            else:
                proxy = await proxy_utils.get_working_proxy(accounts_config, session_proxy) \
                    if session_proxy or settings.USE_PROXY else None

            if not proxy and (settings.USE_PROXY or session_proxy):
                logger.warning(f"{session_name} | Didn't find a working unused proxy for session | Skipping")
                continue
            else:
                max_init_attempts = 2 if settings.AUTO_RESTORE_INVALID_SESSIONS else 1
                
                for attempt in range(max_init_attempts):
                    try:
                        tg_clients.append(UniversalTelegramClient(**client_params))
                        session_config['proxy'] = proxy
                        if accounts_config.get(session_name) != session_config:
                            await config_utils.update_session_config_in_file(session_name, session_config, CONFIG_PATH)
                        break
                    except (AuthKeyUnregisteredError, AuthKeyDuplicatedError, AuthKeyError,
                          SessionPasswordNeededError, PyrogramAuthKeyUnregisteredError,
                           PyrogramSessionPasswordNeededError,
                          PyrogramSessionRevoked, InvalidSession) as e:
                        logger.error(f"{session_name} | Session initialization error: {e}")
                        
                        if attempt < max_init_attempts - 1 and settings.AUTO_RESTORE_INVALID_SESSIONS:
                            backup_manager = SessionBackupManager(SESSIONS_PATH)
                            if backup_manager.backup_exists(session_name):
                                logger.info(f"🔄 {session_name} | Попытка восстановления из бэкапа...")
                                if backup_manager.restore_from_backup(session_name):
                                    logger.info(f"✅ {session_name} | Сессия восстановлена, повторная инициализация...")
                                    await asyncio.sleep(1)
                                    continue
                                else:
                                    logger.error(f"❌ {session_name} | Не удалось восстановить из бэкапа")
                            else:
                                logger.warning(f"⚠️ {session_name} | Бэкап не найден")
                        
                        await move_invalid_session_to_error_folder(session_name)
                        break

    return tg_clients

async def init_config_file() -> None:
    session_paths = get_sessions(SESSIONS_PATH)

    if not session_paths:
        raise FileNotFoundError("Session files not found")
    for session in session_paths:
        session_name = os.path.basename(session)
        parsed_json = config_utils.import_session_json(session)
        if parsed_json:
            accounts_config = config_utils.read_config_file(CONFIG_PATH)
            session_config: dict = deepcopy(accounts_config.get(session_name, {}))
            session_config['user_agent'] = session_config.get('user_agent', generate_random_user_agent())
            session_config['api'] = parsed_json
            if accounts_config.get(session_name) != session_config:
                await config_utils.update_session_config_in_file(session_name, session_config, CONFIG_PATH)

async def run_tasks() -> None:
    await config_utils.restructure_config(CONFIG_PATH)
    await init_config_file()
    
    if settings.AUTO_BACKUP_SESSIONS:
        backup_manager = SessionBackupManager(SESSIONS_PATH)
        backed_up = backup_manager.create_all_backups()
        if backed_up > 0:
            logger.info(f"✅ Создано {backed_up} бэкапов сессий")
    
    base_tasks = []
    
    if settings.AUTO_UPDATE:
        update_manager = UpdateManager()
        base_tasks.append(asyncio.create_task(update_manager.run()))
    
    tg_clients = await get_tg_clients()
    client_tasks = [asyncio.create_task(handle_tapper_session(tg_client=tg_client)) for tg_client in tg_clients]
    
    try:
        if client_tasks:
            await asyncio.gather(*client_tasks, return_exceptions=True)
        
        for task in base_tasks:
            if not task.done():
                task.cancel()
                
        await asyncio.gather(*base_tasks, return_exceptions=True)
        
    except asyncio.CancelledError:
        for task in client_tasks + base_tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*client_tasks + base_tasks, return_exceptions=True)
        raise
        
async def handle_tapper_session(tg_client: UniversalTelegramClient, stats_bot: Optional[object] = None):
    session_name = tg_client.session_name
    max_restore_attempts = 1
    
    for attempt in range(max_restore_attempts + 1):
        try:
            if attempt > 0:
                logger.info(f"{session_name} | Попытка перезапуска после восстановления ({attempt}/{max_restore_attempts})")
                await asyncio.sleep(uniform(2, 5))
            else:
                logger.info(f"{session_name} | Starting session")
            
            await run_tapper(tg_client=tg_client)
            break
            
        except ServerUnavailableError as e:
            logger.warning(f"Сервер недоступен для сессии {session_name}: {e}")
            if attempt < max_restore_attempts and settings.AUTO_RESTORE_INVALID_SESSIONS:
                backup_manager = SessionBackupManager(SESSIONS_PATH)
                if backup_manager.backup_exists(session_name):
                    logger.info(f"🔄 Попытка восстановить сессию {session_name} из бэкапа...")
                    if backup_manager.restore_from_backup(session_name):
                        logger.info(f"✅ Сессия {session_name} восстановлена из бэкапа, повторный запуск...")
                        continue
                    else:
                        logger.error(f"❌ Не удалось восстановить сессию {session_name}")
                        break
                else:
                    logger.warning(f"⚠️ Бэкап для сессии {session_name} не найден")
                    break
            else:
                break
                
        except InvalidSession as e:
            logger.error(f"Invalid session: {session_name}: {e}")
            if settings.DEBUG_LOGGING:
                logger.debug(f"[{session_name}] InvalidSession details: {e}")
            
            if attempt < max_restore_attempts and settings.AUTO_RESTORE_INVALID_SESSIONS:
                backup_manager = SessionBackupManager(SESSIONS_PATH)
                if backup_manager.backup_exists(session_name):
                    logger.info(f"🔄 Попытка восстановить сессию {session_name} из бэкапа...")
                    if backup_manager.restore_from_backup(session_name):
                        logger.info(f"✅ Сессия {session_name} восстановлена из бэкапа, пересоздание клиента...")
                        
                        try:
                            await tg_client.reinit_client()
                            logger.info(f"✅ Клиент {session_name} успешно пересоздан, повторный запуск...")
                            continue
                        except Exception as reinit_error:
                            logger.error(f"❌ Ошибка при пересоздании клиента {session_name}: {reinit_error}")
                            try:
                                await tg_client.disconnect()
                            except:
                                pass
                            await move_invalid_session_to_error_folder(session_name)
                            break
                    else:
                        logger.error(f"❌ Не удалось восстановить сессию {session_name}")
                        try:
                            await tg_client.disconnect()
                        except:
                            pass
                        await move_invalid_session_to_error_folder(session_name)
                        break
                else:
                    logger.warning(f"⚠️ Бэкап для сессии {session_name} не найден")
                    try:
                        await tg_client.disconnect()
                    except:
                        pass
                    await move_invalid_session_to_error_folder(session_name)
                    break
            else:
                try:
                    await tg_client.disconnect()
                except:
                    pass
                await move_invalid_session_to_error_folder(session_name)
                break
        except (AuthKeyUnregisteredError, AuthKeyDuplicatedError, AuthKeyError, 
                SessionPasswordNeededError) as e:
            logger.error(f"Authentication error for Telethon session {session_name}: {e}")
            if settings.DEBUG_LOGGING:
                logger.debug(f"[{session_name}] Telethon Auth error details: {e}")
            
            if attempt < max_restore_attempts and settings.AUTO_RESTORE_INVALID_SESSIONS:
                backup_manager = SessionBackupManager(SESSIONS_PATH)
                if backup_manager.backup_exists(session_name):
                    logger.info(f"🔄 Попытка восстановить сессию {session_name} из бэкапа...")
                    if backup_manager.restore_from_backup(session_name):
                        logger.info(f"✅ Сессия {session_name} восстановлена из бэкапа, пересоздание клиента...")
                        
                        try:
                            await tg_client.reinit_client()
                            logger.info(f"✅ Клиент {session_name} успешно пересоздан, повторный запуск...")
                            continue
                        except Exception as reinit_error:
                            logger.error(f"❌ Ошибка при пересоздании клиента {session_name}: {reinit_error}")
            
            try:
                await tg_client.disconnect()
            except:
                pass
            await move_invalid_session_to_error_folder(session_name)
            break
            
        except (PyrogramAuthKeyUnregisteredError,
                PyrogramSessionPasswordNeededError, PyrogramSessionRevoked) as e:
            logger.error(f"Authentication error for Pyrogram session {session_name}: {e}")
            if settings.DEBUG_LOGGING:
                logger.debug(f"[{session_name}] Pyrogram Auth error details: {e}")
            
            if attempt < max_restore_attempts and settings.AUTO_RESTORE_INVALID_SESSIONS:
                backup_manager = SessionBackupManager(SESSIONS_PATH)
                if backup_manager.backup_exists(session_name):
                    logger.info(f"🔄 Попытка восстановить сессию {session_name} из бэкапа...")
                    if backup_manager.restore_from_backup(session_name):
                        logger.info(f"✅ Сессия {session_name} восстановлена из бэкапа, пересоздание клиента...")
                        
                        try:
                            await tg_client.reinit_client()
                            logger.info(f"✅ Клиент {session_name} успешно пересоздан, повторный запуск...")
                            continue
                        except Exception as reinit_error:
                            logger.error(f"❌ Ошибка при пересоздании клиента {session_name}: {reinit_error}")
            
            try:
                await tg_client.disconnect()
            except:
                pass
            await move_invalid_session_to_error_folder(session_name)
            break
            
        except Exception as e:
            logger.error(f"Unexpected error in session {session_name}: {e}")
            if settings.DEBUG_LOGGING:
                logger.debug(f"[{session_name}] Unexpected exception details: {e}")
            break
    
    logger.info(f"{session_name} | Session ended")
