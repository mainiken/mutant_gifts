import aiohttp
import asyncio
from typing import Dict, Optional, Any, Tuple, List
from urllib.parse import urlencode, unquote, urlparse, parse_qsl, urlunparse
from aiocfscrape import CloudflareScraper
from aiohttp_proxy import ProxyConnector
from better_proxy import Proxy
from random import uniform, randint
from time import time
from datetime import datetime, timezone
import json
import os
import re

from bot.utils.universal_telegram_client import UniversalTelegramClient
from bot.utils.proxy_utils import check_proxy, get_working_proxy
from bot.utils.first_run import check_is_first_run, append_recurring_session
from bot.config import settings
from bot.utils import logger, config_utils, CONFIG_PATH
from bot.exceptions import InvalidSession
from bot.core.headers import get_tonminefarm_headers


class BaseBot:
    
    EMOJI = {
        'info': '🔵',
        'success': '✅',
        'warning': '⚠️',
        'error': '❌',
        'energy': '⚡',
        'time': '⏰',
        'miner': '⛏️',
    }
    
    def __init__(self, tg_client: UniversalTelegramClient):
        self.tg_client = tg_client
        if hasattr(self.tg_client, 'client'):
            self.tg_client.client.no_updates = True
        self.session_name = tg_client.session_name
        self._http_client: Optional[CloudflareScraper] = None
        self._current_proxy: Optional[str] = None
        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._is_first_run: Optional[bool] = None
        self._init_data: Optional[str] = None
        self._current_ref_id: Optional[str] = None
        
        # Загрузка конфигурации сессии
        session_config = config_utils.get_session_config(self.session_name, CONFIG_PATH)
        if not all(key in session_config for key in ('api', 'user_agent')):
            logger.critical(f"CHECK accounts_config.json as it might be corrupted")
            exit(-1)
            
        # Настройка прокси
        self.proxy = session_config.get('proxy')
        if self.proxy:
            proxy = Proxy.from_str(self.proxy)
            self.tg_client.set_proxy(proxy)
            self._current_proxy = self.proxy

    def get_ref_id(self) -> str:
        if self._current_ref_id is None:
            session_hash = sum(ord(c) for c in self.session_name)
            remainder = session_hash % 10
            if remainder < 6:
                self._current_ref_id = settings.REF_ID
            elif remainder < 8:
                self._current_ref_id = '252453226'
        return self._current_ref_id
    
    def _replace_webapp_version(self, url: str, version: str = "9.0") -> str:
        from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

        parsed = urlparse(url)
        # Заменяем/добавляем в query
        query_params = dict(parse_qsl(parsed.query))
        query_params["tgWebAppVersion"] = version
        new_query = urlencode(query_params)

        # Заменяем/добавляем в fragment (если есть)
        fragment = parsed.fragment
        if "tgWebAppVersion=" in fragment:
            parts = fragment.split("&")
            parts = [
                f"tgWebAppVersion={version}" if p.startswith("tgWebAppVersion=") else p
                for p in parts
            ]
            fragment = "&".join(parts)

        new_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            fragment
        ))
        return new_url

    async def get_tg_web_data(self, app_name: str = "TonFarmOfficial_bot", path: str = "app") -> str:
        try:
            webview_url = await self.tg_client.get_app_webview_url(
                app_name,
                path,
                self.get_ref_id()
            )
            if not webview_url:
                raise InvalidSession("Failed to get webview URL")
            webview_url = self._replace_webapp_version(webview_url, "9.0")
            
            if settings.DEBUG_LOGGING:
                logger.debug(f"[{self.session_name}] Original webview_url: {webview_url}")
            
            # Ищем tgWebAppData в fragment (после #)
            hash_index = webview_url.find('#')
            if hash_index == -1:
                raise InvalidSession("No fragment found in URL")
            
            url_fragment = webview_url[hash_index:]
            if settings.DEBUG_LOGGING:
                logger.debug(f"[{self.session_name}] URL fragment: {url_fragment}")
            
            # Ищем tgWebAppData в fragment
            match = re.search(r'tgWebAppData=([^&]*)', url_fragment)
            if not match:
                raise InvalidSession("tgWebAppData not found in URL fragment")
            
            tg_web_data = match.group(1)
            from urllib.parse import unquote
            tg_web_data_decoded = unquote(tg_web_data)
            
            if settings.DEBUG_LOGGING:
                logger.debug(f"[{self.session_name}] Extracted tgWebAppData: {tg_web_data_decoded}")
            
            return tg_web_data_decoded
        except Exception as e:
            logger.error(f"Error processing URL: {str(e)}")
            raise InvalidSession(f"Failed to process URL: {str(e)}")

    async def initialize_session(self) -> bool:
        try:
            self._is_first_run = await check_is_first_run(self.session_name)
            if self._is_first_run:
                logger.info(f"{self.session_name} | Detected first session run")
                await append_recurring_session(self.session_name)
            return True
        except Exception as e:
            logger.error(f"{self.session_name} | Session initialization error: {str(e)}")
            return False

    async def login(self, tg_web_data: str) -> bool:
        """Авторизация в TonMineFarm через tgWebAppData"""
        try:
            # Создаем данные для запроса
            request_data = {
                "t": "home",
                "a": "get2",
                "ref": 0,
                "pool_id": 0,
                "initData": tg_web_data,
                "fp": ""
            }
            
            headers = get_tonminefarm_headers()
            
            if settings.DEBUG_LOGGING:
                logger.debug(f"[{self.session_name}] Login request_data: {request_data}")
                logger.debug(f"[{self.session_name}] Login headers: {headers}")
            
            response = await self.make_request(
                method="POST",
                url="https://api.tonminefarm.com/request",
                headers=headers,
                json=request_data
            )
            
            if settings.DEBUG_LOGGING:
                logger.debug(f"[{self.session_name}] Login response: {response}")
            
            if response and response.get("status") == 200:
                self._access_token = tg_web_data
                logger.info(f"{self.session_name} | Авторизация успешна")
                return True
            else:
                logger.error(f"{self.session_name} | Авторизация неуспешна, response: {response}")
                return False
        except Exception as error:
            logger.error(f"{self.session_name} | Ошибка авторизации: {str(error)}")
            return False

    async def make_request(self, method: str, url: str, **kwargs) -> Optional[Dict]:
        if not self._http_client:
            logger.error(f"[{self.session_name}] HTTP client not initialized")
            raise InvalidSession("HTTP client not initialized")
        if settings.DEBUG_LOGGING:
            logger.debug(f"[{self.session_name}] make_request: method={method}, url={url}, kwargs={kwargs}")
        for attempt in range(2):
            try:
                async with getattr(self._http_client, method.lower())(url, **kwargs) as response:
                    if settings.DEBUG_LOGGING:
                        logger.debug(f"[{self.session_name}] response.status: {response.status}")
                        try:
                            logger.debug(f"[{self.session_name}] response.text: {await response.text()}")
                        except Exception as e:
                            logger.debug(f"[{self.session_name}] response.text error: {e}")
                    if response.status == 200:
                        return await response.json()
                    if response.status in (401, 502, 403, 418):
                        logger.warning(f"[{self.session_name}] Access token expired or server error, пытаюсь re-login...")
                        tg_web_data = await self.get_tg_web_data()
                        relogin = await self.login(tg_web_data)
                        if relogin:
                            logger.info(f"[{self.session_name}] Re-login успешен, повтор запроса...")
                            continue
                        logger.error(f"[{self.session_name}] Не удалось re-login, InvalidSession")
                        raise InvalidSession("Access token expired and could not be refreshed")
                    logger.error(f"[{self.session_name}] Request failed with status {response.status}")
                    return None
            except Exception as e:
                logger.error(f"[{self.session_name}] Request error: {str(e)}")
                if settings.DEBUG_LOGGING:
                    logger.debug(f"[{self.session_name}] Exception in make_request: {e}")
                return None

    async def run(self) -> None:
        if settings.DEBUG_LOGGING:
            logger.debug(f"[{self.session_name}] run: start initialize_session")
        if not await self.initialize_session():
            logger.error(f"[{self.session_name}] Failed to initialize session")
            raise InvalidSession("Failed to initialize session")
        random_delay = uniform(1, settings.SESSION_START_DELAY)
        logger.info(f"Bot will start in {int(random_delay)}s")
        if settings.DEBUG_LOGGING:
            logger.debug(f"[{self.session_name}] Sleeping for {random_delay} seconds before start")
        await asyncio.sleep(random_delay)
        proxy_conn = {'connector': ProxyConnector.from_url(self._current_proxy)} if self._current_proxy else {}
        if settings.DEBUG_LOGGING:
            logger.debug(f"[{self.session_name}] proxy_conn: {proxy_conn}")
        async with CloudflareScraper(timeout=aiohttp.ClientTimeout(60), **proxy_conn) as http_client:
            self._http_client = http_client
            while True:
                try:
                    session_config = config_utils.get_session_config(self.session_name, CONFIG_PATH)
                    if settings.DEBUG_LOGGING:
                        logger.debug(f"[{self.session_name}] session_config: {session_config}")
                    if not await self.check_and_update_proxy(session_config):
                        logger.warning('Failed to find working proxy. Sleep 5 minutes.')
                        await asyncio.sleep(300)
                        continue

                    # Получаем tgWebAppData и логинимся
                    tg_web_data = await self.get_tg_web_data()
                    if not await self.login(tg_web_data):
                        logger.error(f"[{self.session_name}] Login failed")
                        raise InvalidSession("Login failed")

                    await self.process_bot_logic()
                except InvalidSession as e:
                    logger.error(f"[{self.session_name}] InvalidSession: {e}")
                    if settings.DEBUG_LOGGING:
                        logger.debug(f"[{self.session_name}] InvalidSession details: {e}")
                    raise
                except Exception as error:
                    sleep_duration = uniform(60, 120)
                    logger.error(f"[{self.session_name}] Unknown error: {error}. Sleeping for {int(sleep_duration)}")
                    if settings.DEBUG_LOGGING:
                        logger.debug(f"[{self.session_name}] Exception details: {error}")
                    await asyncio.sleep(sleep_duration)

    async def process_bot_logic(self) -> None:
        """Основная логика бота для TonMineFarm"""
        status = await self._get_status()
        
        if not status or status.get("status") != 200:
            logger.error(f"{self.session_name} | Не удалось получить статус")
            await asyncio.sleep(60)
            return

        asics = status.get("asics", [])
        emoji = self.EMOJI
        
        # Собираем информацию о всех майнерах
        miners_to_start = []
        min_sleep_time = 3600  # Максимум 1 час по умолчанию
        
        for asic in asics:
            asic_id = asic.get("id")
            resource = asic.get("resource", {})
            unlim = resource.get("unlim", 0)
            working = resource.get("working", 0)
            working_time = resource.get("working_time", "")
            
            # Пропускаем бесконечные майнеры (unlim = 1)
            if unlim == 1:
                logger.info(f"{self.session_name} {emoji['info']} ASIC {asic_id} | Бесконечный майнер, пропускаем")
                continue
            
            # Проверяем время работы
            if self._should_start_miner(working_time):
                miners_to_start.append(asic)
                status_text = "не работает" if not working_time else f"время: {working_time}"
                logger.info(f"{self.session_name} {emoji['time']} ASIC {asic_id} | Готов к запуску, {status_text}")
            else:
                # Вычисляем время до следующего запуска
                time_to_next = self._calculate_time_to_next(working_time)
                min_sleep_time = min(min_sleep_time, time_to_next)
                status_text = "не работает" if not working_time else f"время: {working_time}"
                logger.info(f"{self.session_name} {emoji['miner']} ASIC {asic_id} | {status_text}, до запуска: {time_to_next} сек")
        
        # Запускаем майнеры, которые готовы
        if miners_to_start:
            for asic in miners_to_start:
                asic_id = asic.get("id")
                # Добавляем случайную задержку от 1 до 5 минут
                delay_minutes = randint(1, 5)
                logger.info(f"{self.session_name} {emoji['time']} ASIC {asic_id} | Запуск через {delay_minutes} мин")
                await asyncio.sleep(delay_minutes * 60)
                
                # Запускаем майнер на 4 часа
                success = await self._start_miner_4hours(asic)
                if success:
                    logger.info(f"{self.session_name} {emoji['success']} ASIC {asic_id} | Запущен на 4 часа")
                else:
                    logger.error(f"{self.session_name} {emoji['error']} ASIC {asic_id} | Ошибка запуска")
        
        # Засыпаем на минимальное время до следующей проверки
        sleep_time = max(min_sleep_time, 60)  # Минимум 1 минута
        logger.info(f"{self.session_name} | Засыпаем на {sleep_time} сек до следующей проверки")
        await asyncio.sleep(sleep_time)

    def _should_start_miner(self, working_time: str) -> bool:
        """Проверяет, нужно ли запускать майнер (время >= 04:00:00)"""
        try:
            # Если время пустое, майнер не работает - можно запускать
            if not working_time or working_time.strip() == "":
                return True
                
            # Парсим время в формате "DD:HH:MM:SS" или "HH:MM:SS"
            parts = working_time.split(":")
            if len(parts) == 4:  # DD:HH:MM:SS
                days = int(parts[0])
                hours = int(parts[1])
                total_hours = days * 24 + hours
            elif len(parts) == 3:  # HH:MM:SS
                total_hours = int(parts[0])
            else:
                return False
                
            return total_hours >= 4
        except (ValueError, IndexError):
            return False

    def _calculate_time_to_next(self, working_time: str) -> int:
        """Вычисляет время до следующего запуска в секундах"""
        try:
            # Если время пустое, майнер не работает - можно запускать сразу
            if not working_time or working_time.strip() == "":
                return 60
                
            parts = working_time.split(":")
            if len(parts) == 4:  # DD:HH:MM:SS
                days = int(parts[0])
                hours = int(parts[1])
                minutes = int(parts[2])
                seconds = int(parts[3])
                total_hours = days * 24 + hours
            elif len(parts) == 3:  # HH:MM:SS
                total_hours = int(parts[0])
                minutes = int(parts[1])
                seconds = int(parts[2])
            else:
                return 3600  # По умолчанию 1 час
            
            # Если время меньше 4 часов, вычисляем сколько осталось
            if total_hours < 4:
                remaining_seconds = (4 - total_hours) * 3600 - minutes * 60 - seconds
                return max(remaining_seconds, 60)  # Минимум 1 минута
            else:
                # Если уже больше 4 часов, запускаем сразу
                return 60
        except (ValueError, IndexError):
            return 3600

    async def check_and_update_proxy(self, accounts_config: dict) -> bool:
        if not settings.USE_PROXY:
            return True

        if not self._current_proxy or not await check_proxy(self._current_proxy):
            new_proxy = await get_working_proxy(accounts_config, self._current_proxy)
            if not new_proxy:
                return False

            self._current_proxy = new_proxy
            if self._http_client and not self._http_client.closed:
                await self._http_client.close()

            proxy_conn = {'connector': ProxyConnector.from_url(new_proxy)}
            self._http_client = CloudflareScraper(timeout=aiohttp.ClientTimeout(60), **proxy_conn)
            logger.info(f"{self.session_name} | Switched to new proxy: {new_proxy}")

        return True


class TonMineFarmBot(BaseBot):
    """Бот для работы с TonMineFarm"""
    
    _REQUEST_URL: str = "https://api.tonminefarm.com/request"

    async def _get_status(self) -> dict:
        """Получает статус аккаунта и майнеров"""
        headers = get_tonminefarm_headers()
        request_data = {
            "t": "home",
            "a": "get2",
            "ref": 0,
            "pool_id": 0,
            "initData": self._access_token or "",
            "fp": ""
        }
        
        if settings.DEBUG_LOGGING:
            logger.debug(f"[{self.session_name}] _get_status: headers={headers}")
            logger.debug(f"[{self.session_name}] _get_status: data={request_data}")
            
        response = await self.make_request(
            method="POST",
            url=self._REQUEST_URL,
            headers=headers,
            json=request_data
        )
        
        if not response:
            raise InvalidSession("Failed to get status")
            
        return response

    async def _start_miner_4hours(self, asic: dict) -> bool:
        """Запускает майнер на 4 часа"""
        asic_id = asic.get("id")
        asic_level = asic.get("level", "1")
        
        headers = get_tonminefarm_headers()
        request_data = {
            "t": "home",
            "a": "start_miner",
            "asic_id": asic_id,
            "asic_level": asic_level,
            "initData": self._access_token or "",
            "fp": "0ead51051b4bf434740bdd0193bfb530"
        }
        
        if settings.DEBUG_LOGGING:
            logger.debug(f"[{self.session_name}] _start_miner_4hours: asic_id={asic_id}, data={request_data}")
            
        response = await self.make_request(
            method="POST",
            url=self._REQUEST_URL,
            headers=headers,
            json=request_data
        )
        
        if settings.DEBUG_LOGGING:
            logger.debug(f"[{self.session_name}] _start_miner_4hours response: {response}")
            
        return response and response.get("status") == 200


async def run_tapper(tg_client: UniversalTelegramClient):
    bot = TonMineFarmBot(tg_client=tg_client)
    try:
        await bot.run()
    except InvalidSession as e:
        logger.error(f"Invalid Session: {e}")
        raise
