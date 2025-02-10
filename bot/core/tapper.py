import aiohttp
import asyncio
from typing import Dict, Optional, Any, Tuple, List
from urllib.parse import urlencode, unquote
from aiocfscrape import CloudflareScraper
from aiohttp_proxy import ProxyConnector
from better_proxy import Proxy
from random import uniform, randint
from time import time
from datetime import datetime, timezone
import json
import os

from bot.utils.universal_telegram_client import UniversalTelegramClient
from bot.utils.proxy_utils import check_proxy, get_working_proxy
from bot.utils.first_run import check_is_first_run, append_recurring_session
from bot.config import settings
from bot.utils import logger, config_utils, CONFIG_PATH
from bot.exceptions import InvalidSession


class BaseBot:
    """
    Базовый класс для создания бота с поддержкой прокси и сессий.
    """
    
    def __init__(self, tg_client: UniversalTelegramClient):
        """
        Инициализация базового бота.
        
        Args:
            tg_client: Клиент Telegram для взаимодействия
        """
        self.tg_client = tg_client
        if hasattr(self.tg_client, 'client'):
            self.tg_client.client.no_updates = True
            
        self.session_name = tg_client.session_name
        self._http_client: Optional[CloudflareScraper] = None
        self._current_proxy: Optional[str] = None
        self._access_token: Optional[str] = None
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
        """
        Получение идентификатора реферала.
        
        Returns:
            str: Идентификатор реферала
        """
        if self._current_ref_id is None:
            random_number = randint(1, 100)
            self._current_ref_id = settings.REF_ID if random_number <= 70 else 'ref_MjI4NjE4Nzk5'
        return self._current_ref_id

    async def get_tg_web_data(self, app_name: str = "app", path: str = "app") -> str:
        """
        Получение данных веб-приложения Telegram.
        
        Args:
            app_name: Название приложения
            path: Путь в приложении
            
        Returns:
            str: Данные веб-приложения
            
        Raises:
            InvalidSession: Если не удалось получить данные
        """
        try:
            webview_url = await self.tg_client.get_app_webview_url(
                app_name,
                path,
                self.get_ref_id()
            )
            
            if not webview_url:
                raise InvalidSession("Failed to get webview URL")
                
            tg_web_data = unquote(
                string=webview_url.split('tgWebAppData=')[1].split('&tgWebAppVersion')[0]
            )
            
            self._init_data = tg_web_data
            return tg_web_data
            
        except Exception as e:
            logger.error(f"Error getting TG Web Data: {str(e)}")
            raise InvalidSession("Failed to get TG Web Data")

    async def check_and_update_proxy(self, accounts_config: dict) -> bool:
        """
        Проверка и обновление прокси при необходимости.
        
        Args:
            accounts_config: Конфигурация аккаунтов
            
        Returns:
            bool: Успешность операции
        """
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
            logger.info(f"Switched to new proxy: {new_proxy}")

        return True

    async def initialize_session(self) -> bool:
        """
        Инициализация сессии и проверка первого запуска.
        
        Returns:
            bool: Успешность инициализации
        """
        try:
            self._is_first_run = await check_is_first_run(self.session_name)
            if self._is_first_run:
                logger.info(f"First run detected for session {self.session_name}")
                await append_recurring_session(self.session_name)
            return True
        except Exception as e:
            logger.error(f"Session initialization error: {str(e)}")
            return False

    async def make_request(self, method: str, url: str, **kwargs) -> Optional[Dict]:
        """
        Выполнение HTTP-запроса с поддержкой прокси и обработкой ошибок.
        
        Args:
            method: HTTP метод
            url: URL для запроса
            **kwargs: Дополнительные параметры запроса
            
        Returns:
            Optional[Dict]: Ответ сервера или None в случае ошибки
        """
        if not self._http_client:
            raise InvalidSession("HTTP client not initialized")

        try:
            async with getattr(self._http_client, method.lower())(url, **kwargs) as response:
                if response.status == 200:
                    return await response.json()
                logger.error(f"Request failed with status {response.status}")
                return None
        except Exception as e:
            logger.error(f"Request error: {str(e)}")
            return None

    async def run(self) -> None:
        """
        Основной цикл работы бота.
        """
        if not await self.initialize_session():
            return

        random_delay = uniform(1, settings.SESSION_START_DELAY)
        logger.info(f"Bot will start in {int(random_delay)}s")
        await asyncio.sleep(random_delay)

        proxy_conn = {'connector': ProxyConnector.from_url(self._current_proxy)} if self._current_proxy else {}
        async with CloudflareScraper(timeout=aiohttp.ClientTimeout(60), **proxy_conn) as http_client:
            self._http_client = http_client

            while True:
                try:
                    session_config = config_utils.get_session_config(self.session_name, CONFIG_PATH)
                    if not await self.check_and_update_proxy(session_config):
                        logger.warning('Failed to find working proxy. Sleep 5 minutes.')
                        await asyncio.sleep(300)
                        continue

                    # Здесь размещается основная логика бота
                    await self.process_bot_logic()
                    
                except InvalidSession as e:
                    raise
                except Exception as error:
                    sleep_duration = uniform(60, 120)
                    logger.error(f"Unknown error: {error}. Sleeping for {int(sleep_duration)}")
                    await asyncio.sleep(sleep_duration)

    async def process_bot_logic(self) -> None:
        """
        Пример метода для реализации основной логики бота.
        Этот метод должен быть переопределен в дочерних классах.
        """
        raise NotImplementedError("Bot logic must be implemented in child class")


async def run_tapper(tg_client: UniversalTelegramClient):
    """
    Функция для запуска бота.
    
    Args:
        tg_client: Клиент Telegram
    """
    bot = BaseBot(tg_client=tg_client)
    try:
        await bot.run()
    except InvalidSession as e:
        logger.error(f"Invalid Session: {e}")
