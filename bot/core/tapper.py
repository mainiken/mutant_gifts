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
from bot.core.headers import get_agentx_headers


class BaseBot:
    
    EMOJI = {
        'info': '🔵',
        'success': '✅',
        'warning': '⚠️',
        'error': '❌',
        'energy': '⚡',
        'time': '⏰',
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

    async def get_tg_web_data(self, app_name: str = "agntxbot", path: str = "node") -> str:
        try:
            webview_url = await self.tg_client.get_app_webview_url(
                app_name,
                path,
                self.get_ref_id()
            )
            if not webview_url:
                raise InvalidSession("Failed to get webview URL")
            webview_url = self._replace_webapp_version(webview_url, "9.0")
            hash_index = webview_url.find('#tgWebAppData=')
            if hash_index == -1:
                raise InvalidSession("tgWebAppData not found in url")
            url_fragment = webview_url[hash_index:]
            match = re.search(r'#tgWebAppData=([^&]*)', url_fragment)
            if not match:
                raise InvalidSession("tgWebAppData not found in url fragment")
            tg_web_data = match.group(1)
            from urllib.parse import unquote
            tg_web_data_decoded = unquote(tg_web_data)
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
        headers = {
            "Accept-Language": "ru-RU,ru;q=0.9,en-NL;q=0.8,en-US;q=0.7,en;q=0.6",
            "Connection": "keep-alive",
            "If-None-Match": 'W/"22f5-XZVuj2p07a8yEuO7gaowbXxXptY"',
            "Origin": "https://app.agentx.pw",
            "Referer": "https://app.agentx.pw/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
            "accept": "application/json",
            "authorization": f"Bearer {tg_web_data}",
        }
        try:
            response = await self.make_request(
                method="GET",
                url="https://api.agentx.pw/main/init",
                headers=headers
            )
            if response and "user" in response:
                self._access_token = tg_web_data
                self._refresh_token = response.get("refreshToken")
                return True
            return False
        except Exception as error:
            logger.error(f"{self.session_name} | Ошибка авторизации: {str(error)}")
            return False

    async def refresh_token(self) -> bool:
        """
        Обновляет access_token с помощью refresh_token.
        Возвращает True при успехе, иначе False.
        """
        if not self._refresh_token:
            return False
        headers = {
            "accept": "application/json",
            "Content-Type": "application/json",
        }
        try:
            async with self._http_client.post(
                "https://api.agentx.pw/auth/refresh",
                headers=headers,
                json={"refreshToken": self._refresh_token}
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    self._access_token = data.get("accessToken")
                    self._refresh_token = data.get("refreshToken")
                    return True
                return False
        except Exception as error:
            logger.error(f"{self.session_name} | Ошибка обновления токена: {str(error)}")
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
                        logger.warning(f"[{self.session_name}] Access token expired or server error, пытаюсь refresh...")
                        refreshed = await self.refresh_token()
                        if refreshed:
                            logger.info(f"[{self.session_name}] Access token refreshed, повтор запроса...")
                            continue
                        logger.warning(f"[{self.session_name}] Refresh не удался, пробую re-login...")
                        tg_web_data = await self.get_tg_web_data()
                        relogin = await self.login(tg_web_data)
                        if relogin:
                            logger.info(f"[{self.session_name}] Re-login успешен, повтор запроса...")
                            continue
                        logger.error(f"[{self.session_name}] Не удалось refresh/re-login, InvalidSession")
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

        raise NotImplementedError("Bot logic must be implemented in child class")

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


class EnergyAgentBot(BaseBot):
    _TOGGLE_URL: str = "https://api.agentx.pw/node/toggle?value={value}"
    _INIT_URL: str = "https://api.agentx.pw/main/init"

    @property
    def energy_tick_seconds(self) -> int:
        return 1

    async def _get_status(self) -> dict:
        headers = get_agentx_headers(self._access_token or "")
        if settings.DEBUG_LOGGING:
            logger.debug(f"[{self.session_name}] _get_status: headers={headers}")
        async with self._http_client.get(self._INIT_URL, headers=headers) as response:
            if settings.DEBUG_LOGGING:
                logger.debug(f"[{self.session_name}] _get_status response.status: {response.status}")
                try:
                    logger.debug(f"[{self.session_name}] _get_status response.text: {await response.text()}")
                except Exception as e:
                    logger.debug(f"[{self.session_name}] _get_status response.text error: {e}")
            if response.status == 200:
                return await response.json()
            logger.error(f"[{self.session_name}] Ошибка запроса: {response.status}")
            raise InvalidSession(f"Ошибка запроса: {response.status}")

    async def _toggle_agent(self, value: bool) -> bool:
        url = self._TOGGLE_URL.format(value=str(value).lower())
        headers = get_agentx_headers(self._access_token or "")
        if settings.DEBUG_LOGGING:
            logger.debug(f"[{self.session_name}] _toggle_agent: url={url}, headers={headers}, value={value}")
        async with self._http_client.post(url, headers=headers, data="") as response:
            if settings.DEBUG_LOGGING:
                logger.debug(f"[{self.session_name}] _toggle_agent response.status: {response.status}")
                try:
                    logger.debug(f"[{self.session_name}] _toggle_agent response.text: {await response.text()}")
                except Exception as e:
                    logger.debug(f"[{self.session_name}] _toggle_agent response.text error: {e}")
            return response.status == 200

    async def process_bot_logic(self) -> None:
        status = await self._get_status()
        user = status.get("user", {})
        energy = user.get("energy", 0)
        max_energy = user.get("max_energy", 0)
        last_energy_consumed = user.get("last_energy_consumed", 0)
        is_node_started = user.get("is_node_started", False)
        ENERGY_MIN = 100
        emoji = self.EMOJI
        if energy > ENERGY_MIN and not is_node_started:
            await self._toggle_agent(True)
            logger.info(f"{self.session_name} {emoji['success']} Agent started | {emoji['energy']}Energy: {energy}/{max_energy}")
        elif energy <= ENERGY_MIN and is_node_started:
            await self._toggle_agent(False)
            logger.info(f"{self.session_name} {emoji['error']} Agent stopped | {emoji['energy']}Energy: {energy}/{max_energy}")
        if energy < max_energy:
            ticks_needed = max_energy - energy
            from datetime import datetime, timedelta
            last_dt = datetime.utcfromtimestamp(last_energy_consumed / 1000)
            full_recovery_dt = last_dt + timedelta(seconds=ticks_needed * 2)  # 1 energy = 2 seconds
            now = datetime.utcnow()
            sleep_seconds = max((full_recovery_dt - now).total_seconds(), 60)
            logger.info(f"{self.session_name} {emoji['time']} Waiting for {emoji['energy']}energy recovery: {int(sleep_seconds)} sec.")
            await asyncio.sleep(sleep_seconds)
        else:
            await asyncio.sleep(60)

async def run_tapper(tg_client: UniversalTelegramClient):
    bot = EnergyAgentBot(tg_client=tg_client)
    try:
        await bot.run()
    except InvalidSession as e:
        logger.error(f"Invalid Session: {e}")
        raise
