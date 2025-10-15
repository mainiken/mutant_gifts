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
from yarl import URL

from bot.utils.universal_telegram_client import UniversalTelegramClient
from bot.utils.proxy_utils import check_proxy, get_working_proxy
from bot.utils.first_run import check_is_first_run, append_recurring_session
from bot.config import settings
from bot.utils import logger, config_utils, CONFIG_PATH
from bot.exceptions import InvalidSession
from bot.core.session_manager import SessionManager



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
        if not isinstance(session_config, dict):
            logger.warning(f"{self.session_name} | Invalid session config format: {type(session_config).__name__}. Resetting to empty dict.")
            session_config = {}
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
                self._current_ref_id = 'r_252453226'
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

    async def get_tg_web_data(self, app_name: str = "mutant_gifts_bot", path: str = "mutantgifts") -> str:
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
                        
                        # Для MutantGiftsBot используем новую логику с проверкой времени жизни токена
                        if hasattr(self, '_restart_authorization'):
                            try:
                                reauth_success = await self._restart_authorization()
                                if reauth_success:
                                    logger.info(f"[{self.session_name}] Re-authorization успешен, повтор запроса...")
                                    continue
                                logger.error(f"[{self.session_name}] Не удалось re-authorize, InvalidSession")
                                raise InvalidSession("Access token expired and could not be refreshed")
                            except Exception as e:
                                logger.error(f"[{self.session_name}] Ошибка при re-authorization: {e}")
                                raise InvalidSession("Access token expired and could not be refreshed")
                        else:
                            # Старая логика для других ботов
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


class MutantGiftsBot(BaseBot):
    """Бот для работы с Mutant Gifts"""
    
    EMOJI = {
        'info': '🔵',
        'success': '✅',
        'warning': '⚠️',
        'error': '❌',
        'energy': '⚡',
        'time': '⏰',
        'battle': '⚔️',
        'character': '🎯',
        'activity': '📋',
        'leaderboard': '🏆',
        'disenchant': '🗑️',
    }
    
    def __init__(self, tg_client: UniversalTelegramClient):
        super().__init__(tg_client)
        self._jwt_token: Optional[str] = None
        self._token_created_time: Optional[float] = None
        self._base_url: str = "https://mutant-gifts.xyz"
        self._session_cookies: Dict[str, str] = {}
        self._init_data: Optional[str] = None
        self._ssl_disabled: bool = False
        
        # Менеджер сессии для отслеживания рефиллов
        self.session_manager = SessionManager(self.session_name)
        
        # Статистика для отслеживания
        self._stats = {
            'unranked_battles': 0,
            'ranked_battles': 0,
            'total_coins_earned': 0,
            'total_gems_earned': 0,
            'total_rating_earned': 0,
            'battles_won': 0,
            'battles_lost': 0,
            'unranked_refills': 0,
            'ranked_refills': 0,
            'total_gems_spent_on_refills': 0,
            'mutations_performed': 0
        }
        
    def _is_token_expired(self) -> bool:
        """Проверяет, истек ли токен"""
        if not self._token_created_time:
            logger.debug(f"[{self.session_name}] Токен не создан, требуется авторизация")
            return True
        
        token_lifetime_seconds = settings.TOKEN_LIFETIME_HOURS * 3600
        token_age = time() - self._token_created_time
        is_expired = token_age > token_lifetime_seconds
        
        if is_expired:
            logger.warning(f"[{self.session_name}] {self.EMOJI['time']} Токен истек: возраст {token_age:.0f}с > лимит {token_lifetime_seconds}с")
        else:
            remaining_time = token_lifetime_seconds - token_age
            logger.debug(f"[{self.session_name}] {self.EMOJI['time']} Токен действителен: осталось {remaining_time:.0f}с")
        
        return is_expired
    
    async def _restart_authorization(self) -> bool:
        """Перезапускает авторизацию с получением новых init_data"""
        try:
            logger.info(f"[{self.session_name}] {self.EMOJI['warning']} Перезапуск авторизации...")
            
            # Получаем новые init_data
            tg_web_data = await self.get_tg_web_data()
            if not tg_web_data:
                logger.error(f"[{self.session_name}] {self.EMOJI['error']} Не удалось получить новые init_data")
                return False
            
            # Сбрасываем старый токен
            logger.debug(f"[{self.session_name}] Сброс старого токена и cookies")
            self._jwt_token = None
            self._token_created_time = None
            self._session_cookies.clear()
            
            # Выполняем новую авторизацию
            auth_result = await self.authenticate(tg_web_data)
            if auth_result:
                logger.info(f"[{self.session_name}] {self.EMOJI['success']} Перезапуск авторизации успешен")
            else:
                logger.error(f"[{self.session_name}] {self.EMOJI['error']} Не удалось выполнить новую авторизацию")
            
            return auth_result
            
        except Exception as error:
            logger.error(f"[{self.session_name}] {self.EMOJI['error']} Ошибка при перезапуске авторизации: {error}")
            return False

    def get_mutant_gifts_headers(self) -> Dict[str, str]:
        """Заголовки для API Mutant Gifts"""
        from bot.core.headers import get_mutant_gifts_headers
        return get_mutant_gifts_headers()
    
    async def authenticate(self, tg_web_data: str) -> bool:
        """Авторизация в Mutant Gifts через tgWebAppData для получения JWT токена"""
        try:
            # Попробуем получить JWT токен через обмен initData → jwt
            # Согласно бандлу фронта, используется POST /auth/session с полями
            # { initData, refCode }
            headers = self.get_mutant_gifts_headers()
            # Уточняем браузерные заголовки для корректной установки Set-Cookie
            headers.setdefault("Referer", "https://mutant-gifts.xyz/")
            headers.setdefault("Origin", "https://mutant-gifts.xyz")
            session_payload = {
                "initData": tg_web_data,
                "refCode": self.get_ref_id() or ""
            }

            try:
                async with self._http_client.post(
                    f"{self._base_url}/apiv1/auth/session",
                    headers=headers,
                    json=session_payload,
                ) as sess_resp:
                    if settings.DEBUG_LOGGING:
                        logger.debug(f"[{self.session_name}] /apiv1/auth/session status: {sess_resp.status}")
                    if sess_resp.status in (200, 201):
                        # Сервер должен проставить jwt в Set-Cookie
                        resp_cookie = sess_resp.cookies.get('jwt') if sess_resp.cookies else None
                        if resp_cookie and resp_cookie.value:
                            self._jwt_token = resp_cookie.value
                            self._token_created_time = time()
                            self._session_cookies['jwt'] = resp_cookie.value
                            logger.info(f"[{self.session_name}] {self.EMOJI['success']} JWT токен получен из Set-Cookie, время жизни: {settings.TOKEN_LIFETIME_HOURS}ч")
                    # Проверим cookie_jar клиента на предмет jwt
                    if not self._jwt_token and hasattr(self._http_client, 'cookie_jar'):
                        try:
                            jar_cookies = self._http_client.cookie_jar.filter_cookies(URL(self._base_url))
                            jar_jwt = jar_cookies.get('jwt') if jar_cookies else None
                            if jar_jwt and getattr(jar_jwt, 'value', None):
                                self._jwt_token = jar_jwt.value
                                self._token_created_time = time()
                                self._session_cookies['jwt'] = jar_jwt.value
                                logger.info(f"[{self.session_name}] {self.EMOJI['success']} JWT токен получен из cookie_jar, время жизни: {settings.TOKEN_LIFETIME_HOURS}ч")
                        except Exception as e:
                            if settings.DEBUG_LOGGING:
                                logger.debug(f"[{self.session_name}] cookie_jar after /auth/session error: {e}")
            except Exception as e:
                if settings.DEBUG_LOGGING:
                    logger.debug(f"[{self.session_name}] /auth/session request error: {e}")

            # Если JWT не получили через /auth/session — альтернативно посетим главную
            query_params = {
                "tgWebAppStartParam": self.get_ref_id(),
                "tgWebAppVersion": "9.0",
                "tgWebAppPlatform": "android",
                "tgWebAppData": tg_web_data,
            }
            auth_url = f"{self._base_url}/?{urlencode(query_params)}"
            
            if settings.DEBUG_LOGGING:
                logger.debug(f"[{self.session_name}] Visiting auth URL: {auth_url}")
            
            # Посещаем страницу для установки cookies
            # При проблемах SSL можем использовать отключенный SSL при FIX_CERT
            get_kwargs = {"headers": headers}
            if settings.FIX_CERT:
                get_kwargs["ssl"] = False
            async with self._http_client.get(auth_url, **get_kwargs) as response:
                if settings.DEBUG_LOGGING:
                    logger.debug(f"[{self.session_name}] Auth page response status: {response.status}")
                
                # Пробуем достать jwt из Set-Cookie заголовков ответа
                resp_cookie = response.cookies.get('jwt') if response.cookies else None
                if resp_cookie and resp_cookie.value:
                    self._jwt_token = resp_cookie.value
                    self._token_created_time = time()
                    self._session_cookies['jwt'] = resp_cookie.value
                    logger.info(f"[{self.session_name}] {self.EMOJI['success']} JWT токен получен из GET Set-Cookie, время жизни: {settings.TOKEN_LIFETIME_HOURS}ч")
                
            # Если не нашли в самом ответе — пробуем получить из cookie_jar клиента
            if not self._jwt_token and hasattr(self._http_client, 'cookie_jar'):
                try:
                    jar_cookies = self._http_client.cookie_jar.filter_cookies(URL(self._base_url))
                    jar_jwt = jar_cookies.get('jwt') if jar_cookies else None
                    if jar_jwt and getattr(jar_jwt, 'value', None):
                        self._jwt_token = jar_jwt.value
                        self._token_created_time = time()
                        self._session_cookies['jwt'] = jar_jwt.value
                        logger.info(f"[{self.session_name}] {self.EMOJI['success']} JWT токен получен из cookie_jar, время жизни: {settings.TOKEN_LIFETIME_HOURS}ч")
                except Exception as e:
                    if settings.DEBUG_LOGGING:
                        logger.debug(f"[{self.session_name}] cookie_jar error: {e}")

            # Дополнительная попытка: дернуть профиль с init data в заголовке,
            # некоторые приложения аутентифицируют по нему
            if not self._jwt_token:
                init_header_candidates = [
                    "X-Telegram-Init-Data",
                    "X-Init-Data",
                    "X-Telegram-Auth",
                ]
                for header_name in init_header_candidates:
                    try:
                        headers_with_init = {**headers, header_name: tg_web_data}
                        if settings.DEBUG_LOGGING:
                            logger.debug(
                                f"[{self.session_name}] Try auth via header {header_name}"
                            )
                        prof_kwargs = {"headers": headers_with_init}
                        if settings.FIX_CERT:
                            prof_kwargs["ssl"] = False
                        async with self._http_client.get(
                            f"{self._base_url}/apiv1/profile", **prof_kwargs
                        ) as prof_resp:
                            if settings.DEBUG_LOGGING:
                                logger.debug(
                                    f"[{self.session_name}] profile(status={prof_resp.status}) via {header_name}"
                                )
                            if prof_resp.status == 200:
                                self._init_data = tg_web_data
                                # Сохраняем, какой именно заголовок работает
                                self._session_cookies["__init_header_name"] = header_name
                                logger.info(f"{self.session_name} | Авторизация через {header_name}")
                                return True
                            resp_cookie = (
                                prof_resp.cookies.get('jwt') if prof_resp.cookies else None
                            )
                            if resp_cookie and resp_cookie.value:
                                self._jwt_token = resp_cookie.value
                                self._token_created_time = time()
                                self._session_cookies['jwt'] = resp_cookie.value
                                logger.info(f"[{self.session_name}] {self.EMOJI['success']} JWT токен получен из профиля Set-Cookie, время жизни: {settings.TOKEN_LIFETIME_HOURS}ч")
                                break
                        # Проверяем cookie_jar после запроса профиля
                        if not self._jwt_token and hasattr(self._http_client, 'cookie_jar'):
                            jar_cookies = self._http_client.cookie_jar.filter_cookies(URL(self._base_url))
                            jar_jwt = jar_cookies.get('jwt') if jar_cookies else None
                            if jar_jwt and getattr(jar_jwt, 'value', None):
                                self._jwt_token = jar_jwt.value
                                self._token_created_time = time()
                                self._session_cookies['jwt'] = jar_jwt.value
                                logger.info(f"[{self.session_name}] {self.EMOJI['success']} JWT токен получен из профиля cookie_jar, время жизни: {settings.TOKEN_LIFETIME_HOURS}ч")
                                break
                    except Exception as e:
                        if settings.DEBUG_LOGGING:
                            logger.debug(
                                f"[{self.session_name}] header auth attempt failed: {header_name}: {e}"
                            )
            
            # Если ни JWT, ни успешной авторизации через init data — ошибка
            if not self._jwt_token and not self._init_data:
                logger.error(f"{self.session_name} | Не удалось аутентифицироваться")
                return False
            
            logger.info(f"{self.session_name} | JWT токен установлен: {self._jwt_token[:20]}...")
            
            # Теперь пробуем получить профиль с JWT токеном
            profile_response = await self.make_mutant_request(
                method="GET",
                url=f"{self._base_url}/apiv1/profile"
            )
            
            if settings.DEBUG_LOGGING:
                logger.debug(f"[{self.session_name}] Profile response: {profile_response}")
            
            if profile_response:
                logger.info(f"{self.session_name} | Авторизация в Mutant Gifts успешна")
                return True
            else:
                logger.error(f"{self.session_name} | Не удалось получить профиль, response: {profile_response}")
                return False
                
        except Exception as error:
            logger.error(f"{self.session_name} | Ошибка авторизации в Mutant Gifts: {str(error)}")
            return False
    
    async def make_mutant_request(self, method: str, url: str, **kwargs) -> Optional[Dict]:
        """Выполнение запросов к API Mutant Gifts с JWT токеном"""
        if not self._http_client:
            logger.error(f"[{self.session_name}] HTTP client not initialized")
            raise InvalidSession("HTTP client not initialized")
        
        # Объединяем cookies: переданные в kwargs + сессионные
        cookies = kwargs.get('cookies', {}).copy()
        if self._jwt_token:
            cookies.update(self._session_cookies)
        if cookies:
            kwargs['cookies'] = cookies

        # Если используем init_data аутентификацию — добавим заголовок
        headers = kwargs.get('headers', {}).copy()
        if self._init_data and "authorization" not in {k.lower() for k in headers}:
            header_name = self._session_cookies.get("__init_header_name", "X-Telegram-Init-Data")
            headers[header_name] = self._init_data
            kwargs['headers'] = headers
        
        if settings.DEBUG_LOGGING:
            logger.debug(f"[{self.session_name}] make_mutant_request: method={method}, url={url}, kwargs={kwargs}")
        
        for attempt in range(2):
            try:
                async with getattr(self._http_client, method.lower())(url, **kwargs) as response:
                    if settings.DEBUG_LOGGING:
                        logger.debug(f"[{self.session_name}] response.status: {response.status}")
                        try:
                            response_text = await response.text()
                            logger.debug(f"[{self.session_name}] response.text: {response_text}")
                        except Exception as e:
                            logger.debug(f"[{self.session_name}] response.text error: {e}")
                    
                    if response.status in [200, 201]:  # 201 - Created, тоже успешный статус
                        try:
                            return await response.json()
                        except Exception as e:
                            logger.error(f"[{self.session_name}] Failed to parse JSON response: {e}")
                            return None
                    
                    if response.status in (401, 403):
                        logger.warning(f"[{self.session_name}] JWT токен истек, пытаюсь re-authenticate...")
                        
                        # Используем новую логику с проверкой времени жизни токена
                        try:
                            reauth_success = await self._restart_authorization()
                            if reauth_success:
                                logger.info(f"[{self.session_name}] Re-authorization успешен, повтор запроса...")
                                continue
                            logger.error(f"[{self.session_name}] Не удалось re-authorize, InvalidSession")
                            raise InvalidSession("JWT token expired and could not be refreshed")
                        except Exception as e:
                            logger.error(f"[{self.session_name}] Ошибка при re-authorization: {e}")
                            raise InvalidSession("JWT token expired and could not be refreshed")
                    
                    logger.error(f"[{self.session_name}] Request failed with status {response.status}")
                    return None
                    
            except Exception as e:
                logger.error(f"[{self.session_name}] Request error: {str(e)}")
                if settings.DEBUG_LOGGING:
                    logger.debug(f"[{self.session_name}] Exception in make_mutant_request: {e}")
                return None
    
    async def get_profile(self) -> Optional[Dict]:
        """Получение профиля пользователя"""
        try:
            response = await self.make_mutant_request(
                method="GET",
                url=f"{self._base_url}/apiv1/profile"
            )
            
            if response and response.get("id"):
                if settings.DEBUG_LOGGING:
                    logger.debug(f"{self.session_name} | {self.EMOJI['info']} Профиль получен успешно")
                return response
            else:
                logger.error(f"{self.session_name} | {self.EMOJI['error']} Не удалось получить профиль, response: {response}")
                return None
                
        except Exception as error:
            logger.error(f"{self.session_name} | Ошибка получения профиля: {str(error)}")
            return None
    
    async def mutate_gems(self) -> Optional[Dict]:
        """Получение персонажа через мутацию за стартовые гемы"""
        try:
            response = await self.make_mutant_request(
                method="POST",
                url=f"{self._base_url}/apiv1/mutations/gems",
                json=None
            )
            if response and response.get("id"):
                if settings.DEBUG_LOGGING:
                    logger.debug(f"{self.session_name} | Получен персонаж мутацией: {response.get('name')}")
                return response
            logger.error(f"{self.session_name} | Не удалось выполнить мутацию, response: {response}")
            return None
        except Exception as error:
            logger.error(f"{self.session_name} | Ошибка мутации: {str(error)}")
            return None

    async def get_mutations_info(self) -> Optional[Dict]:
        """Получение информации о доступных мутациях"""
        try:
            response = await self.make_mutant_request(
                method="GET",
                url=f"{self._base_url}/apiv1/mutations"
            )
            if response is not None:
                if settings.DEBUG_LOGGING:
                    logger.debug(f"{self.session_name} | Данные по мутациям получены")
                return response
            logger.error(f"{self.session_name} | Не удалось получить данные по мутациям")
            return None
        except Exception as error:
            logger.error(f"{self.session_name} | Ошибка получения данных по мутациям: {str(error)}")
            return None

    async def level_up_character(self, character_id: str, current_level: int) -> bool:
        """Улучшение уровня персонажа (обновленная версия API)"""
        try:
            next_level = current_level + 1
            payload = {
                "id": character_id,
                "level": next_level
            }
            response = await self.make_mutant_request(
                method="POST",
                url=f"{self._base_url}/apiv1/characters/{character_id}/level_up",
                json=payload
            )
            if response and response.get("success") is True:
                if settings.DEBUG_LOGGING:
                    logger.debug(f"{self.session_name} | Персонаж {character_id} улучшен до уровня {next_level}")
                return True
            logger.error(f"{self.session_name} | Не удалось улучшить персонажа {character_id}, response: {response}")
            return False
        except Exception as error:
            logger.error(f"{self.session_name} | Ошибка улучшения персонажа {character_id}: {str(error)}")
            return False

    async def get_character_upgrade_cost(self, character_id: str, current_level: int) -> int:
        """Получение стоимости прокачки персонажа"""
        try:
            # Используем формулу на основе реальных наблюдений
            # Из логов видно что стоимость растет экспоненциально
            # Примерные значения: уровень 31->32 = ~323117 монет
            
            # Формула основана на наблюдениях из игры
            if current_level <= 10:
                base_cost = 100
                multiplier = 1.2
            elif current_level <= 20:
                base_cost = 500
                multiplier = 1.3
            elif current_level <= 30:
                base_cost = 2000
                multiplier = 1.4
            else:
                # Для высоких уровней (30+)
                base_cost = 10000
                multiplier = 1.5
            
            calculated_cost = int(base_cost * (current_level ** multiplier))
            
            if settings.DEBUG_LOGGING:
                logger.debug(f"{self.session_name} | Рассчитана стоимость прокачки для {character_id} (уровень {current_level}): {calculated_cost}")
            
            return calculated_cost
            
        except Exception as error:
            logger.error(f"{self.session_name} | Ошибка получения стоимости прокачки {character_id}: {str(error)}")
            # Возвращаем базовую стоимость в случае ошибки
            return 1000 * current_level

    async def disenchant_character(self, character_id: str) -> bool:
        """Распыление персонажа"""
        try:
            response = await self.make_mutant_request(
                method="DELETE",
                url=f"{self._base_url}/apiv1/characters/{character_id}"
            )
            if response and response.get("success") is True:
                if settings.DEBUG_LOGGING:
                    logger.debug(f"{self.session_name} | Персонаж {character_id} распылен")
                return True
            logger.error(f"{self.session_name} | Не удалось распылить персонажа {character_id}, response: {response}")
            return False
        except Exception as error:
            logger.error(f"{self.session_name} | Ошибка распыления персонажа {character_id}: {str(error)}")
            return False
    
    async def refill_unranked_energy(self) -> bool:
        """Восстановление обычной энергии за гемы"""
        try:
            response = await self.make_mutant_request(
                method="POST",
                url=f"{self._base_url}/apiv1/profile/refill_unranked_energy",
                json={}
            )
            if response and response.get("success") is True:
                # Записываем выполненный рефилл
                self.session_manager.record_unranked_refill()
                return True
            logger.error(f"{self.session_name} | {self.EMOJI['error']} Не удалось восстановить обычную энергию, response: {response}")
            return False
        except Exception as error:
            logger.error(f"{self.session_name} | Ошибка восстановления обычной энергии: {str(error)}")
            return False
    
    async def refill_ranked_energy(self) -> bool:
        """Восстановление рейтинговой энергии за гемы"""
        try:
            response = await self.make_mutant_request(
                method="POST",
                url=f"{self._base_url}/apiv1/profile/refill_ranked_energy",
                json={}
            )
            if response and response.get("success") is True:
                # Записываем выполненный рефилл
                self.session_manager.record_ranked_refill()
                return True
            logger.error(f"{self.session_name} | {self.EMOJI['error']} Не удалось восстановить рейтинговую энергию, response: {response}")
            return False
        except Exception as error:
            logger.error(f"{self.session_name} | Ошибка восстановления рейтинговой энергии: {str(error)}")
            return False
    
    def get_refill_cost(self, refill_count: int) -> int:
        """Возвращает стоимость восстановления энергии в гемах"""
        if refill_count == 1:
            return 60
        elif refill_count == 2:
            return 120
        else:  # 3+ восстановления
            return 240
    
    async def smart_energy_refill(self, profile: Dict, energy_type: str = "ranked") -> bool:
        """Умное восстановление энергии на основе настроек
        
        Args:
            profile: Профиль пользователя
            energy_type: Тип энергии 'ranked' или 'unranked'
        
        Returns:
            bool: True если восстановление прошло успешно
        """
        if not settings.AUTO_REFILL_ENERGY:
            return False
        
        if not isinstance(profile, dict):
            return False
        
        current_gems = profile.get('gems', 0)
        
        # Обновляем стоимости рефилов из профиля API
        self.session_manager.update_refill_costs_from_profile(profile)
        
        # Определяем количество уже сделанных восстановлений и получаем реальную стоимость
        if energy_type == "ranked":
            refills_made = self._stats['ranked_refills']
            next_refill_cost = profile.get('refill_price_ranked_gems') or self.session_manager.get_next_ranked_refill_cost()
        else:
            refills_made = self._stats['unranked_refills']
            next_refill_cost = profile.get('refill_price_unranked_gems') or self.session_manager.get_next_unranked_refill_cost()
        
        # Проверяем, можно ли делать восстановление
        if refills_made >= settings.MAX_ENERGY_REFILLS:
            if settings.DEBUG_LOGGING:
                logger.debug(f"{self.session_name} | 🚫 Достигнут лимит восстановлений {energy_type} энергии: {refills_made}/{settings.MAX_ENERGY_REFILLS}")
            return False
        
        # Проверяем достаточно ли гемов
        if current_gems < next_refill_cost:
            logger.warning(f"{self.session_name} | 💵 Недостаточно гемов для восстановления {energy_type} энергии: {current_gems} < {next_refill_cost}")
            return False
        
        # Выполняем восстановление
        logger.info(f"{self.session_name} | 💰 Восстанавливаем {energy_type} энергию за {next_refill_cost} гемов (восстановление #{refills_made + 1})")
        
        if energy_type == "ranked":
            success = await self.refill_ranked_energy()
            if success:
                self._stats['ranked_refills'] += 1
                self._stats['total_gems_spent_on_refills'] += next_refill_cost
        else:
            success = await self.refill_unranked_energy()
            if success:
                self._stats['unranked_refills'] += 1
                self._stats['total_gems_spent_on_refills'] += next_refill_cost
        
        return success
    
    async def smart_refill_strategy(self, profile: Dict, ranked_energy: int, unranked_energy: int) -> bool:
        """Умная стратегия рефилла энергии с оптимизацией по стоимости
        
        Логика:
        1. ВСЕГДА приоритет ранкед энергии над анранкед
        2. Выбираем самый дешевый рефилл из доступных
        3. Рефиллим по очереди: сначала самый дешевый, потом следующий по стоимости
        """
        if not settings.AUTO_REFILL_ENERGY:
            return False
            
        # Обновляем стоимости рефилов из профиля API
        self.session_manager.update_refill_costs_from_profile(profile)
            
        current_gems = profile.get('gems', 0)
        
        # Получаем актуальные стоимости рефиллов
        ranked_cost = profile.get('refill_price_ranked_gems') or self.session_manager.get_next_ranked_refill_cost()
        unranked_cost = profile.get('refill_price_unranked_gems') or self.session_manager.get_next_unranked_refill_cost()
        
        # Определяем какие типы энергии нуждаются в рефилле
        needs_ranked_refill = ranked_energy == 0
        needs_unranked_refill = unranked_energy == 0
        
        # Если ничего не нужно рефиллить
        if not needs_ranked_refill and not needs_unranked_refill:
            return False
        
        # СЛУЧАЙ 1: Оба типа энергии нуждаются в рефилле - выбираем самый дешевый
        if needs_ranked_refill and needs_unranked_refill:
            # Ранкед всегда имеет приоритет, но если он дороже и недоступен, пробуем анранкед
            if current_gems >= ranked_cost:
                logger.info(f"{self.session_name} | 💰 Рефилл рейтинговой энергии за {ranked_cost} гемов (ПРИОРИТЕТ - оба типа нужны)")
                if await self.refill_ranked_energy():
                    self.session_manager.record_ranked_refill()
                    logger.info(f"{self.session_name} | ✅ Рейтинговая энергия восстановлена!")
                    return True
                else:
                    logger.warning(f"{self.session_name} | ⚠️ Не удалось восстановить рейтинговую энергию")
                    return False
            elif current_gems >= unranked_cost:
                logger.info(f"{self.session_name} | 💰 Рефилл обычной энергии за {unranked_cost} гемов (ранкед недоступен)")
                if await self.refill_unranked_energy():
                    self.session_manager.record_unranked_refill()
                    logger.info(f"{self.session_name} | ✅ Обычная энергия восстановлена!")
                    return True
                else:
                    logger.warning(f"{self.session_name} | ⚠️ Не удалось восстановить обычную энергию")
                    return False
            else:
                min_cost = min(ranked_cost, unranked_cost)
                gems_needed = min_cost - current_gems
                logger.info(f"{self.session_name} | 💸 Недостаточно гемов для любого рефилла. Нужно: {gems_needed} гемов")
                return False
        
        # СЛУЧАЙ 2: Только ранкед нуждается в рефилле
        elif needs_ranked_refill:
            if current_gems >= ranked_cost:
                logger.info(f"{self.session_name} | 💰 Рефилл рейтинговой энергии за {ranked_cost} гемов (ПРИОРИТЕТ)")
                if await self.refill_ranked_energy():
                    self.session_manager.record_ranked_refill()
                    logger.info(f"{self.session_name} | ✅ Рейтинговая энергия восстановлена!")
                    return True
                else:
                    logger.warning(f"{self.session_name} | ⚠️ Не удалось восстановить рейтинговую энергию")
                    return False
            else:
                gems_needed = ranked_cost - current_gems
                logger.info(f"{self.session_name} | 💸 Недостаточно гемов для рейтингового рефилла. Нужно: {gems_needed} гемов")
                return False
        
        # СЛУЧАЙ 3: Только анранкед нуждается в рефилле
        elif needs_unranked_refill:
            if current_gems >= unranked_cost:
                logger.info(f"{self.session_name} | 💰 Рефилл обычной энергии за {unranked_cost} гемов")
                if await self.refill_unranked_energy():
                    self.session_manager.record_unranked_refill()
                    logger.info(f"{self.session_name} | ✅ Обычная энергия восстановлена!")
                    return True
                else:
                    logger.warning(f"{self.session_name} | ⚠️ Не удалось восстановить обычную энергию")
                    return False
            else:
                gems_needed = unranked_cost - current_gems
                logger.info(f"{self.session_name} | 💸 Недостаточно гемов для обычного рефилла. Нужно: {gems_needed} гемов")
                return False
        
        return False

    async def perform_first_run_tutorial(self) -> None:
        """Прохождение первичного обучения при первом запуске сессии.
        Шаги:
        1) POST /apiv1/mutations/gems — получить стартового персонажа
        2) GET  /apiv1/profile — проверить обновление профиля
        3) GET  /apiv1/mutations — получить информацию о мутациях
        4) GET  /apiv1/characters — получить список персонажей
        5) POST /apiv1/characters/{id}/level_up — улучшить полученного персонажа
        6) GET  /apiv1/profile — убедиться в применении изменений
        """
        try:
            logger.info(f"{self.session_name} | {self.EMOJI['info']} Первый запуск: прохождение обучения")

            new_character: Optional[Dict] = await self.mutate_gems()
            await asyncio.sleep(1)

            await self.get_profile()
            await asyncio.sleep(1)

            await self.get_mutations_info()
            await asyncio.sleep(1)

            characters = await self.get_characters()
            await asyncio.sleep(1)

            character_to_level_id: Optional[str] = None
            if new_character and new_character.get("id"):
                character_to_level_id = new_character["id"]
            elif characters:
                pinned_sorted = sorted(
                    [c for c in characters if c.get("pin_index") is not None],
                    key=lambda c: c.get("pin_index", 0)
                )
                if pinned_sorted:
                    character_to_level_id = pinned_sorted[-1]["id"]
                else:
                    character_to_level_id = characters[0]["id"]

            if character_to_level_id:
                # Находим персонажа для получения его уровня
                char_to_level = next((c for c in characters if c.get('id') == character_to_level_id), None)
                if char_to_level:
                    current_level = char_to_level.get('level', 1)
                    await self.level_up_character(character_to_level_id, current_level)
                await asyncio.sleep(1)

            await self.get_profile()
            logger.info(f"{self.session_name} | {self.EMOJI['success']} Обучение завершено")
        except Exception as error:
            logger.error(f"{self.session_name} | Ошибка при прохождении обучения: {str(error)}")

    async def get_characters(self) -> Optional[List[Dict]]:
        """Получение списка персонажей пользователя"""
        try:
            response = await self.make_mutant_request(
                method="GET",
                url=f"{self._base_url}/apiv1/characters"
            )
            
            if response and "characters" in response:
                characters = response["characters"]
                if settings.DEBUG_LOGGING:
                    logger.debug(f"{self.session_name} | {self.EMOJI['character']} Получено {len(characters)} персонажей")
                return characters
            else:
                logger.error(f"{self.session_name} | {self.EMOJI['error']} Не удалось получить персонажей, response: {response}")
                return None
                
        except Exception as error:
            logger.error(f"{self.session_name} | Ошибка получения персонажей: {str(error)}")
            return None
    
    async def get_battles_history(self) -> Optional[List[Dict]]:
        """Получение истории боев"""
        try:
            response = await self.make_mutant_request(
                method="GET",
                url=f"{self._base_url}/apiv1/battles"
            )
            
            if response and "battles" in response:
                battles = response["battles"]
                if settings.DEBUG_LOGGING:
                    logger.debug(f"{self.session_name} | {self.EMOJI['battle']} Получено {len(battles)} боев в истории")
                return battles
            else:
                logger.error(f"{self.session_name} | {self.EMOJI['error']} Не удалось получить историю боев, response: {response}")
                return None
                
        except Exception as error:
            logger.error(f"{self.session_name} | Ошибка получения истории боев: {str(error)}")
            return None
    
    def select_best_characters(self, characters: List[Dict], count: int = 3) -> List[str]:
        """Выбор лучших персонажей для боя"""
        if not characters:
            return []
        
        # Сначала выбираем закрепленных персонажей (pinned)
        pinned_characters = [char for char in characters if char.get('pin_index') is not None]
        
        if pinned_characters:
            # Сортируем закрепленных персонажей по pin_index
            pinned_characters.sort(key=lambda char: char.get('pin_index', 0))
            selected = pinned_characters[:count]
            character_ids = [char['id'] for char in selected]
            
            if settings.DEBUG_LOGGING:
                logger.debug(f"{self.session_name} | {self.EMOJI['character']} Выбраны закрепленные персонажи: {[char.get('name', 'Unknown') for char in selected]}")
            return character_ids
        
        # Если нет закрепленных персонажей, выбираем лучших по характеристикам
        sorted_characters = sorted(
            characters,
            key=lambda char: (
                char.get('level', 1),
                self._get_rarity_value(char.get('rarity', 'Common')),
                char.get('attack_damage', 0) + char.get('hp', 0)
            ),
            reverse=True
        )
        
        # Берем первых count персонажей
        selected = sorted_characters[:count]
        character_ids = [char['id'] for char in selected]
        
        if settings.DEBUG_LOGGING:
            logger.debug(f"{self.session_name} | {self.EMOJI['character']} Выбраны персонажи для боя: {[char.get('name', 'Unknown') for char in selected]}")
        return character_ids
    
    def _get_rarity_value(self, rarity: str) -> int:
        """Получение числового значения редкости персонажа"""
        rarity_values = {
            'Common': 1,
            'Uncommon': 2,
            'Rare': 3,
            'Epic': 4,
            'Legendary': 5
        }
        return rarity_values.get(rarity, 1)

    def _get_rarity_rank(self, rarity: str) -> int:
        ranking = {
            'Legendary': 5,
            'Epic': 4,
            'Rare': 3,
            'Uncommon': 2,
            'Common': 1
        }
        return ranking.get(rarity, 1)

    def _sort_by_rarity_priority(self, characters: List[Dict]) -> List[Dict]:
        safe_chars = [c for c in characters if isinstance(c, dict)]
        return sorted(
            safe_chars,
            key=lambda c: (
                self._get_rarity_rank(c.get('rarity', 'Common')),
                c.get('level', 1),
                c.get('attack_damage', 0) + c.get('hp', 0),
            ),
            reverse=True
        )

    def _get_mutation_gems_price(self, profile: Optional[Dict]) -> int:
        if not isinstance(profile, dict):
            return 0
        mutation_price = profile.get('mutation_price', {})
        if isinstance(mutation_price, dict):
            gems_price = mutation_price.get('gems')
            if isinstance(gems_price, int):
                return gems_price
            try:
                return int(gems_price)
            except Exception:
                return 0
        return 0

    async def change_pin(self, character_id: str, pin_index: Optional[int]) -> bool:
        try:
            payload: Dict[str, Any] = {"id": character_id, "pin_index": pin_index}
            headers = self.get_mutant_gifts_headers()
            response = await self.make_mutant_request(
                method="POST",
                url=f"{self._base_url}/apiv1/characters/{character_id}/change_pin",
                json=payload,
                headers=headers
            )
            if response and response.get("success") is True:
                if settings.DEBUG_LOGGING:
                    logger.debug(f"{self.session_name} | Персонаж {character_id} закреплен как {pin_index}")
                return True
            logger.error(f"{self.session_name} | Не удалось закрепить персонажа {character_id}, response: {response}")
            return False
        except Exception as error:
            logger.error(f"{self.session_name} | Ошибка закрепления персонажа {character_id}: {str(error)}")
            return False

    async def ensure_best_pins(self, characters: List[Dict]) -> List[str]:
        safe_chars = [c for c in characters if isinstance(c, dict)]
        desired = self._sort_by_rarity_priority([c for c in safe_chars if c])[:3]
        desired_ids = [c['id'] for c in desired]

        # Текущие пины
        current_pins = {c['id']: c.get('pin_index') for c in characters if c.get('pin_index') is not None}

        # Назначаем пины 0,1,2 в порядке убывания приоритета
        for idx, character in enumerate(desired):
            current_idx = character.get('pin_index')
            if current_idx != idx:
                await self.change_pin(character['id'], idx)

        # Остальные сняем с пинов
        for character in safe_chars:
            if character['id'] not in desired_ids and character.get('pin_index') is not None:
                await self.change_pin(character['id'], None)

        return desired_ids

    async def auto_disenchant_low_rarity(self, characters: List[Dict]) -> List[Dict]:
        """Автоматическое распыление карточек низкой редкости"""
        if not settings.AUTO_DISENCHANT:
            return characters
        
        if not isinstance(characters, list) or not characters:
            return characters
            
        disenchant_rarities = settings.disenchant_rarities
        if not disenchant_rarities:
            return characters
        
        # Находим закрепленных персонажей (не распыляем)
        pinned_ids = {char['id'] for char in characters 
                     if isinstance(char, dict) and char.get('pin_index') is not None}
        
        # Находим кандидатов на распыление
        candidates_to_disenchant = []
        for char in characters:
            if not isinstance(char, dict) or char.get('id') in pinned_ids:
                continue
                
            char_rarity = char.get('rarity', 'Unknown')
            if char_rarity in disenchant_rarities:
                candidates_to_disenchant.append(char)
        
        if not candidates_to_disenchant:
            if settings.DEBUG_LOGGING:
                logger.debug(f"{self.session_name} | 🗑️ Нет карточек для распыления")
            return characters
        
        logger.info(f"{self.session_name} | 🗑️ Найдено {len(candidates_to_disenchant)} карточек для распыления ({', '.join(disenchant_rarities)})")
        
        disenchanted_count = 0
        remaining_characters = characters.copy()
        
        for char in candidates_to_disenchant:
            char_id = char.get('id')
            char_name = char.get('name', 'Unknown')
            char_rarity = char.get('rarity', 'Unknown')
            
            if await self.disenchant_character(char_id):
                disenchanted_count += 1
                logger.info(f"{self.session_name} | 🗑️ Распылен: {char_name} ({char_rarity})")
                # Удаляем из списка
                remaining_characters = [c for c in remaining_characters 
                                      if not (isinstance(c, dict) and c.get('id') == char_id)]
                # Небольшая задержка между распылениями
                await asyncio.sleep(uniform(0.5, 1.5))
            else:
                logger.error(f"{self.session_name} | ❌ Не удалось распылить {char_name} ({char_rarity})")
        
        if disenchanted_count > 0:
            logger.info(f"{self.session_name} | ✨ Распылено {disenchanted_count} карточек!")
            # Обновляем список персонажей
            updated_characters = await self.get_characters()
            return updated_characters or remaining_characters
        
        return remaining_characters

    async def auto_upgrade_pinned(self, characters: List[Dict], coins: int) -> Tuple[int, List[Dict]]:
        if not settings.AUTO_UPGRADE:
            return coins, characters
            
        updated_characters = characters
        pinned = [c for c in characters if isinstance(c, dict) and c.get('pin_index') is not None]
        # Сортируем пины по индексу 0..2
        pinned.sort(key=lambda c: c.get('pin_index', 0))

        if not pinned:
            logger.info(f"{self.session_name} | 📌 Нет закрепленных персонажей для прокачки")
            return coins, characters

        logger.info(f"{self.session_name} | 🔧 Начинаем прокачку {len(pinned)} закрепленных персонажей")
        
        for char in pinned:
            char_id = char.get('id')
            char_name = char.get('name', 'Unknown')
            char_level = char.get('level', 1)
            pin_index = char.get('pin_index', 0)
            
            logger.info(f"{self.session_name} | 🔧 Прокачиваем {char_name} (пин {pin_index}, уровень {char_level})")
            
            # Получаем актуальный профиль для проверки баланса
            current_profile = await self.get_profile()
            if not current_profile:
                logger.error(f"{self.session_name} | ❌ Не удалось получить профиль для проверки баланса")
                break
                
            current_coins = current_profile.get('coins', 0)
            
            # Получаем актуальные данные персонажей
            fresh_characters = await self.get_characters()
            if not fresh_characters:
                logger.error(f"{self.session_name} | ❌ Не удалось получить актуальные данные персонажей")
                break
                
            # Находим актуального персонажа
            fresh_char = next((c for c in fresh_characters if isinstance(c, dict) and c.get('id') == char_id), None)
            if not fresh_char:
                logger.error(f"{self.session_name} | ❌ Персонаж {char_name} не найден в актуальных данных")
                continue
                
            current_level = fresh_char.get('level', 1)
            
            # Получаем стоимость прокачки через новый метод
            cost = await self.get_character_upgrade_cost(char_id, current_level)
            
            if cost <= 0:
                logger.warning(f"{self.session_name} | ⚠️ Некорректная стоимость прокачки для {char_name}: {cost}, пропускаем")
                continue
            
            # Прокачиваем пока хватает монет
            upgrades_count = 0
            while cost > 0 and (current_coins - cost) >= settings.MIN_COINS_BALANCE:
                logger.info(f"{self.session_name} | 💰 Прокачиваем {char_name} с {current_level} до {current_level + 1} за {cost} монет (баланс: {current_coins})")
                
                success = await self.level_up_character(char_id, current_level)
                if not success:
                    logger.error(f"{self.session_name} | ❌ Не удалось прокачать {char_name}")
                    break
                    
                upgrades_count += 1
                current_coins -= cost
                current_level += 1
                
                await asyncio.sleep(0.5)
                
                # Получаем обновленные данные для следующей итерации
                updated_profile = await self.get_profile()
                if updated_profile:
                    current_coins = updated_profile.get('coins', current_coins)
                
                updated_chars = await self.get_characters()
                if updated_chars:
                    updated_characters = updated_chars
                    fresh_char = next((c for c in updated_chars if isinstance(c, dict) and c.get('id') == char_id), fresh_char)
                    current_level = fresh_char.get('level', current_level)
                    
                    # Получаем стоимость следующего уровня через новый метод
                    cost = await self.get_character_upgrade_cost(char_id, current_level)
                    
                    if cost <= 0:
                        logger.warning(f"{self.session_name} | ⚠️ Некорректная стоимость следующего уровня для {char_name}: {cost}, завершаем")
                        break
                else:
                    # Если не удалось получить обновленные данные, прерываем цикл
                    logger.error(f"{self.session_name} | ❌ Не удалось получить обновленные данные персонажей, завершаем прокачку")
                    break
            
            if upgrades_count > 0:
                logger.info(f"{self.session_name} | ✅ {char_name} прокачан на {upgrades_count} уровней (итоговый уровень: {current_level})")
            else:
                logger.info(f"{self.session_name} | 💸 Недостаточно монет для прокачки {char_name} (нужно: {cost}, доступно: {current_coins - settings.MIN_COINS_BALANCE})")

        # Получаем финальные данные
        final_profile = await self.get_profile()
        final_coins = final_profile.get('coins', coins) if final_profile else coins
        
        final_characters = await self.get_characters()
        if final_characters:
            updated_characters = final_characters
            
        return final_coins, updated_characters
    
    async def start_battle(self, character_ids: List[str], battle_type: str = "Unranked") -> Optional[Dict]:
        """Запуск боя с выбранными персонажами"""
        try:
            battle_data = {
                "battle": {
                    "character_ids": character_ids,
                    "battle_type": battle_type
                }
            }
            
            if settings.DEBUG_LOGGING:
                logger.debug(f"{self.session_name} | Battle data: {battle_data}")
            
            response = await self.make_mutant_request(
                method="POST",
                url=f"{self._base_url}/apiv1/battles",
                json=battle_data
            )
            
            if response:
                if settings.DEBUG_LOGGING:
                    logger.debug(f"{self.session_name} | {self.EMOJI['battle']} Бой {battle_type} запущен успешно")
                return response
            else:
                logger.error(f"{self.session_name} | {self.EMOJI['error']} Не удалось запустить бой {battle_type}")
                return None
                
        except Exception as error:
            logger.error(f"{self.session_name} | Ошибка запуска боя {battle_type}: {str(error)}")
            return None
    
    def analyze_battle_result(self, battle_logs: List[Dict]) -> Dict:
        """Анализ результатов боя"""
        if not battle_logs:
            return {}
        
        analysis = {
            'total_actions': len(battle_logs),
            'attacks': 0,
            'heals': 0,
            'critical_hits': 0,
            'blocks': 0,
            'rage_activations': 0
        }
        
        for log in battle_logs:
            action = log.get('action', '')
            
            if action == 'attack':
                analysis['attacks'] += 1
                if log.get('critical', False):
                    analysis['critical_hits'] += 1
            elif action == 'cast_heal':
                analysis['heals'] += 1
            elif action == 'block_damage':
                analysis['blocks'] += 1
            elif action == 'rage_increased':
                analysis['rage_activations'] += 1
        
        return analysis
    
    async def process_battles(self, characters: List[Dict], battle_type: str, energy: int) -> None:
        """Обработка боев для определенного типа"""
        logger.info(f"{self.session_name} | {self.EMOJI['battle']} {battle_type} бои: {energy} энергии")
        
        # Выбираем лучших персонажей
        character_ids = self.select_best_characters(characters, 3)
        if not character_ids:
            logger.error(f"{self.session_name} | {self.EMOJI['error']} Нет персонажей для боя")
            return
        
        # Запускаем бои пока есть энергия
        battles_fought = 0
        logger.info(f"{self.session_name} | {self.EMOJI['battle']} Начинаем {battle_type} бои. Энергии: {energy}")
        
        while energy > 0:  # Убираем ограничение, бьемся пока есть энергия
            if settings.DEBUG_LOGGING:
                logger.debug(f"{self.session_name} | Запуск {battle_type} боя #{battles_fought + 1}")
            
            battle_result = await self.start_battle(character_ids, battle_type)
            if battle_result:
                battles_fought += 1
                energy -= 1
                logger.info(f"{self.session_name} | {self.EMOJI['battle']} Бой #{battles_fought} завершен. Осталось энергии: {energy}")
                
                # Обновляем статистику
                if battle_type == "Unranked":
                    self._stats['unranked_battles'] += 1
                else:
                    self._stats['ranked_battles'] += 1
                
                # Проверяем результат боя
                if battle_result.get('is_won', False):
                    self._stats['battles_won'] += 1
                else:
                    self._stats['battles_lost'] += 1
                
                # Анализируем результаты боя
                if 'logs' in battle_result:
                    analysis = self.analyze_battle_result(battle_result['logs'])
                    if settings.DEBUG_LOGGING:
                        logger.debug(f"{self.session_name} | Результаты боя: {analysis}")
                
                # Случайная задержка между боями 5–36 секунд
                await asyncio.sleep(uniform(5, 36))
            else:
                logger.error(f"{self.session_name} | {self.EMOJI['error']} Не удалось запустить бой, прерываем")
                break
        
        if battles_fought > 0:
            logger.info(f"{self.session_name} | {self.EMOJI['success']} Завершено {battles_fought} {battle_type} боев")
        else:
            logger.info(f"{self.session_name} | {self.EMOJI['warning']} Не удалось провести ни одного {battle_type} боя")
    
    def print_session_stats(self, sleep_duration: int) -> None:
        """Вывод статистики сессии перед сном"""
        total_battles = self._stats['unranked_battles'] + self._stats['ranked_battles']
        
        # Общая статистика восстановлений
        total_refills = self._stats['unranked_refills'] + self._stats['ranked_refills']
        
        if total_battles > 0 or total_refills > 0:
            logger.info(f"{self.session_name} | {'='*50}")
            logger.info(f"{self.session_name} | 📊 СТАТИСТИКА СЕССИИ:")
            logger.info(f"{self.session_name} | {'='*50}")
            
            if total_battles > 0:
                logger.info(f"{self.session_name} | {self.EMOJI['battle']} Всего боев: {total_battles}")
                logger.info(f"{self.session_name} |   ├─ Обычные бои: {self._stats['unranked_battles']}")
                logger.info(f"{self.session_name} |   └─ Рейтинговые бои: {self._stats['ranked_battles']}")
                logger.info(f"{self.session_name} | 🏆 Победы: {self._stats['battles_won']} | Поражения: {self._stats['battles_lost']}")
            
            if total_refills > 0:
                logger.info(f"{self.session_name} | {self.EMOJI['energy']} Восстановлений энергии: {total_refills}")
                logger.info(f"{self.session_name} |   ├─ Обычная: {self._stats['unranked_refills']}")
                logger.info(f"{self.session_name} |   └─ Рейтинговая: {self._stats['ranked_refills']}")
                logger.info(f"{self.session_name} | 💸 Потрачено гемов на восстановление: {self._stats['total_gems_spent_on_refills']}")
            
            logger.info(f"{self.session_name} | 💰 Монеты заработано: {self._stats['total_coins_earned']}")
            logger.info(f"{self.session_name} | 💸 Камни заработано: {self._stats['total_gems_earned']}")
            logger.info(f"{self.session_name} | ⭐ Рейтинг заработано: {self._stats['total_rating_earned']}")
            logger.info(f"{self.session_name} | {'='*50}")
        
        # Показываем время сна в читаемом формате
        hours = sleep_duration // 3600
        minutes = (sleep_duration % 3600) // 60
        seconds = sleep_duration % 60
        
        if hours > 0:
            time_str = f"{hours}ч {minutes}м {seconds}с"
        elif minutes > 0:
            time_str = f"{minutes}м {seconds}с"
        else:
            time_str = f"{seconds}с"
        
        logger.info(f"{self.session_name} | {self.EMOJI['time']} Ближайшее событие: сон на {time_str}")
        logger.info(f"{self.session_name} | {'='*50}")
    
    def calculate_sleep_duration(self, unranked_energy: int, ranked_energy: int, 
                                next_unranked_energy_at: int, next_ranked_energy_at: int) -> int:
        """Рассчитываем время сна до накопления 6 единиц энергии.
        - Обычные бои: максимум 6, +1 каждый 1 час.
        - Рейтинговые бои: максимум 6, +1 каждые 3 часа.
        Ждем 6 единиц любого типа энергии - какой накопится быстрее."""
        import datetime

        # Если у нас уже есть 6+ энергии - просыпаемся сразу
        if unranked_energy >= 6 or ranked_energy >= 6:
            return 60  # Достаточно энергии - начинаем бои

        now_ts = int(datetime.datetime.now().timestamp())

        def time_to_six_energy(current_energy: int, next_at: int, max_energy: int, interval_sec: int) -> int:
            target_energy = 6
            if current_energy >= target_energy:
                return 0  # Уже достаточно энергии
            
            # Не можем накопить 6, если максимум меньше
            actual_target = min(target_energy, max_energy)
            if current_energy >= actual_target:
                return 0
                
            needed_energy = actual_target - current_energy
            
            # Время до ближайшего тика
            if next_at and next_at > now_ts:
                first_tick_time = next_at - now_ts
            else:
                first_tick_time = interval_sec
                
            # Остальные тики
            remaining_ticks = max(0, needed_energy - 1)
            remaining_time = remaining_ticks * interval_sec
            
            return first_tick_time + remaining_time

        # Время до 6 единиц каждого типа
        unranked_six_time = time_to_six_energy(unranked_energy, next_unranked_energy_at, 6, 1 * 3600)
        ranked_six_time = time_to_six_energy(ranked_energy, next_ranked_energy_at, 6, 3 * 3600)

        # Просыпаемся когда любой тип достигнет 6 единиц
        sleep_time = min(unranked_six_time, ranked_six_time) + 30  # небольшой буфер
        return max(300, sleep_time)  # Минимум 5 минут сна
    
    async def login(self, tg_web_data: str) -> bool:
        """Авторизация в Mutant Gifts (переопределяем метод BaseBot)"""
        return await self.authenticate(tg_web_data)
    
    async def run(self) -> None:
        """Основной цикл работы Mutant Gifts бота"""
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
        
        # Настраиваем коннектор с учетом FIX_CERT
        proxy_conn: Dict[str, Any]
        if self._current_proxy:
            proxy_conn = {'connector': ProxyConnector.from_url(self._current_proxy)}
        else:
            proxy_conn = {}
            if settings.FIX_CERT:
                proxy_conn['connector'] = aiohttp.TCPConnector(ssl=False)
                self._ssl_disabled = True
        if settings.DEBUG_LOGGING:
            logger.debug(f"[{self.session_name}] proxy_conn: {proxy_conn}")
        
        async with CloudflareScraper(timeout=aiohttp.ClientTimeout(60), **proxy_conn) as http_client:
            self._http_client = http_client
            while True:
                try:
                    session_config = config_utils.get_session_config(self.session_name, CONFIG_PATH)
                    if settings.DEBUG_LOGGING:
                        logger.debug(f"[{self.session_name}] session_config: {session_config}")

                    # Для подбора рабочего прокси нужен полный конфиг аккаунтов (а не конфиг одной сессии)
                    try:
                        full_accounts_config = config_utils.read_config_file(CONFIG_PATH)
                    except Exception:
                        full_accounts_config = {}
                    
                    if not await self.check_and_update_proxy(full_accounts_config):
                        logger.warning('Failed to find working proxy. Sleep 5 minutes.')
                        await asyncio.sleep(300)
                        continue

                    # Получаем tgWebAppData и авторизуемся
                    tg_web_data = await self.get_tg_web_data()
                    if not await self.authenticate(tg_web_data):
                        logger.error(f"[{self.session_name}] Authentication failed")
                        raise InvalidSession("Authentication failed")

                    # Проходим обучение при первом запуске
                    if self._is_first_run:
                        await self.perform_first_run_tutorial()

                    # Запускаем основную логику Mutant Gifts
                    await self.process_mutant_gifts_logic()
                    
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
    
    async def claim_daily_streak(self) -> bool:
        """Получение ежедневной награды за вход"""
        try:
            # Сначала получаем профиль, чтобы узнать текущий стрик
            profile = await self.get_profile()
            if not profile or not isinstance(profile, dict):
                logger.error(f"{self.session_name} | {self.EMOJI['error']} Не удалось получить профиль перед клеймом ежедневной награды")
                return False
                
            daily_streak = profile.get('daily_streak', 0)
            can_claim = profile.get('can_claim_daily_streak', False)
            
            if not can_claim:
                logger.info(f"{self.session_name} | {self.EMOJI['info']} Ежедневная награда уже получена. Текущий стрик: {daily_streak} дней")
                return False
            
            # Выполняем запрос на получение награды
            response = await self.make_mutant_request(
                method="POST",
                url=f"{self._base_url}/apiv1/profile/claim_daily_streak"
            )
            
            if response and response.get("success") is True:
                # Получаем обновленный профиль для проверки нового стрика и полученных гемов
                updated_profile = await self.get_profile()
                if updated_profile and isinstance(updated_profile, dict):
                    new_streak = updated_profile.get('daily_streak', 0)
                    gems_before = profile.get('gems', 0)
                    gems_after = updated_profile.get('gems', 0)
                    gems_earned = gems_after - gems_before
                    
                    logger.info(f"{self.session_name} | {self.EMOJI['success']} Ежедневная награда за вход получена! Стрик: {new_streak} дней, получено гемов: {gems_earned}")
                else:
                    logger.info(f"{self.session_name} | {self.EMOJI['success']} Ежедневная награда за вход получена! Стрик: {daily_streak + 1} дней")
                return True
            else:
                if settings.DEBUG_LOGGING:
                    logger.debug(f"{self.session_name} | Не удалось получить ежедневную награду, response: {response}")
                return False
                
        except Exception as error:
            logger.error(f"{self.session_name} | Ошибка получения ежедневной награды: {str(error)}")
            return False
    
    async def get_activities(self) -> Optional[List[Dict]]:
        """Получение списка ежедневных заданий"""
        try:
            response = await self.make_mutant_request(
                method="GET",
                url=f"{self._base_url}/apiv1/activities"
            )
            
            if response and "activities" in response:
                activities = response["activities"]
                if settings.DEBUG_LOGGING:
                    logger.debug(f"{self.session_name} | {self.EMOJI['info']} Получено {len(activities)} заданий")
                return activities
            else:
                logger.error(f"{self.session_name} | {self.EMOJI['error']} Не удалось получить задания, response: {response}")
                return None
                
        except Exception as error:
            logger.error(f"{self.session_name} | Ошибка получения заданий: {str(error)}")
            return None
    
    async def claim_activity(self, activity_id: str) -> bool:
        """Получение награды за выполненное задание"""
        try:
            payload = {"id": activity_id}
            response = await self.make_mutant_request(
                method="POST",
                url=f"{self._base_url}/apiv1/activities/{activity_id}/claim",
                json=payload
            )
            
            if response and response.get("success") is True:
                logger.info(f"{self.session_name} | {self.EMOJI['success']} Награда за задание {activity_id} получена")
                return True
            else:
                if settings.DEBUG_LOGGING:
                    logger.debug(f"{self.session_name} | Не удалось получить награду за задание {activity_id}, response: {response}")
                return False
                
        except Exception as error:
            logger.error(f"{self.session_name} | Ошибка получения награды за задание {activity_id}: {str(error)}")
            return False
    
    async def claim_referrals_reward(self) -> bool:
        """Получение награды гемов за рефералов"""
        try:
            response = await self.make_mutant_request(
                method="POST",
                url=f"{self._base_url}/apiv1/profile/claim_referrals_reward"
            )
            
            if response and response.get("success") is True:
                logger.info(f"{self.session_name} | {self.EMOJI['success']} Награда за рефералов получена")
                return True
            else:
                if settings.DEBUG_LOGGING:
                    logger.debug(f"{self.session_name} | Не удалось получить награду за рефералов, response: {response}")
                return False
                
        except Exception as error:
            logger.error(f"{self.session_name} | Ошибка получения награды за рефералов: {str(error)}")
            return False
    
    async def process_activities(self) -> None:
        """Обработка ежедневных заданий и получение наград"""
        activities = await self.get_activities()
        if not activities:
            logger.warning(f"{self.session_name} | {self.EMOJI['warning']} Не удалось получить список заданий")
            return
        
        completed_activities = []
        for activity in activities:
            if not isinstance(activity, dict):
                continue
                
            activity_id = activity.get("id")
            current_progress = activity.get("current_progress", 0)
            target_progress = activity.get("target_progress", 1)
            reward_gems = activity.get("reward_gems", 0)
            activity_type = activity.get("type", "unknown")
            
            # Проверяем, выполнено ли задание (current_progress >= target_progress)
            if current_progress >= target_progress and activity.get("status") != 30:
                completed_activities.append((activity_id, activity_type, reward_gems))
        
        if completed_activities:
            logger.info(f"{self.session_name} | {self.EMOJI['info']} Найдено {len(completed_activities)} выполненных заданий")
            
            # Получаем награды за выполненные задания
            total_claimed = 0
            total_gems = 0
            for activity_id, activity_type, reward_gems in completed_activities:
                if await self.claim_activity(activity_id):
                    total_claimed += 1
                    total_gems += reward_gems
                    # Небольшая задержка между запросами
                    await asyncio.sleep(uniform(0.5, 1.5))
            
            if total_claimed > 0:
                logger.info(f"{self.session_name} | {self.EMOJI['success']} Получено {total_claimed} наград на сумму {total_gems} гемов")
                # Обновляем профиль после получения наград
                await self.get_profile()
        else:
            if settings.DEBUG_LOGGING:
                logger.debug(f"{self.session_name} | {self.EMOJI['info']} Нет выполненных заданий")
    
    async def process_mutant_gifts_logic(self) -> None:
        """Основная логика бота для Mutant Gifts с исправленными приоритетами
        
        Логика:
        1. Проверяем карты и прокачиваем уровни карт
        2. ПРИОРИТЕТ: Проверяем таски и забираем гемы (для рефиллов)
        3. Бьем обычные бои
        4. Бьем рейтинговые бои
        5. Делаем рефилл за гемы (с приоритетом на ранговые)
        6. Делаем мутации за оставшиеся гемы (с запасом на рефиллы)
        7. Повторяем цикл или идем спать
        """
        # Сбрасываем счетчик мутаций в начале нового цикла
        self._stats['mutations_performed'] = 0
        
        # Проверяем время жизни токена и перезапускаем авторизацию при необходимости
        if self._is_token_expired():
            logger.info(f"{self.session_name} | {self.EMOJI['warning']} Токен истек, перезапускаем авторизацию...")
            if not await self._restart_authorization():
                logger.error(f"{self.session_name} | {self.EMOJI['error']} Не удалось перезапустить авторизацию")
                await asyncio.sleep(300)  # Ждем 5 минут перед повторной попыткой
                return
        
        # Получаем профиль пользователя
        profile = await self.get_profile()
        
        if not profile or not isinstance(profile, dict):
            logger.error(f"{self.session_name} | {self.EMOJI['error']} Не удалось получить профиль")
            await asyncio.sleep(60)
            return
        
        # Извлекаем данные профиля
        username = profile.get('username', 'Unknown')
        unranked_energy = profile.get('unranked_energy', 0)
        ranked_energy = profile.get('ranked_energy', 0)
        coins = profile.get('coins', 0)
        gems = profile.get('gems', 0)
        next_unranked_energy_at = profile.get('next_unranked_energy_at')
        next_ranked_energy_at = profile.get('next_ranked_energy_at')
        can_claim_daily_streak = profile.get('can_claim_daily_streak', False)
        has_claimable_activity = profile.get('has_claimable_activity', False)
        
        # Выводим статистику рефиллов на начало сессии
        session_stats = self.session_manager.get_session_stats()
        logger.info(f"{self.session_name} | 📊 Статистика дня: потрачено {session_stats['total_gems_spent_today']} гемов")
        
        # Выводим компактную информацию о профиле
        logger.info(f"{self.session_name} | {self.EMOJI['character']} {username} | {self.EMOJI['energy']} {unranked_energy}({ranked_energy}) | 💰 {coins} | 💸 {gems}")
        logger.info(f"{self.session_name} | 💎 Следующий рейтинговый рефилл: {session_stats['next_ranked_refill_cost']} гемов")
        
        # Получаем ежедневную награду за вход, если доступна
        if can_claim_daily_streak:
            logger.info(f"{self.session_name} | {self.EMOJI['info']} Доступна ежедневная награда за вход")
            if await self.claim_daily_streak():
                # Обновляем профиль после получения награды
                profile = await self.get_profile()
                if profile:
                    gems = profile.get('gems', gems)
                    logger.info(f"{self.session_name} | {self.EMOJI['success']} Профиль обновлен после получения ежедневной награды. Гемов: {gems}")
        
        # ШАГ 1: Получаем персонажей и настраиваем их
        characters = await self.get_characters()
        if not characters:
            logger.error(f"{self.session_name} | {self.EMOJI['error']} Не удалось получить персонажей")
            await asyncio.sleep(60)
            return
        if not isinstance(characters, list):
            logger.error(f"{self.session_name} | {self.EMOJI['error']} Некорректный формат персонажей: {type(characters).__name__}")
            await asyncio.sleep(60)
            return
        
        # Авто-распыление карточек низкой редкости
        if settings.AUTO_DISENCHANT:
            characters = await self.auto_disenchant_low_rarity(characters)
        
        # Обеспечиваем правильные пины по приоритету редкости
        selected_ids = await self.ensure_best_pins(characters)
        characters = await self.get_characters() or characters

        # Авто-улучшение: только закрепленных карт, при балансе выше MIN_COINS_BALANCE
        if settings.AUTO_UPGRADE:
            coins, characters = await self.auto_upgrade_pinned(characters, coins)
        
        # ШАГ 2: Обработка заданий (активностей) и получение наград - ПРИОРИТЕТ!
        # Сначала получаем гемы из заданий, чтобы потом их можно было использовать для рефиллов
        if has_claimable_activity:
            logger.info(f"{self.session_name} | {self.EMOJI['activity']} Обрабатываем доступные задания")
            await self.process_activities()
            # Обновляем профиль после получения наград
            updated_profile = await self.get_profile()
            if updated_profile:
                gems = updated_profile.get('gems', gems)
                logger.info(f"{self.session_name} | {self.EMOJI['success']} Профиль обновлен после получения наград. Гемов: {gems}")

        # ШАГ 2.1: Получение награды гемов за рефералов
        logger.info(f"{self.session_name} | {self.EMOJI['activity']} Пытаемся получить награду за рефералов")
        if await self.claim_referrals_reward():
            # Обновляем профиль после получения награды за рефералов
            updated_profile = await self.get_profile()
            if updated_profile:
                gems = updated_profile.get('gems', gems)
                logger.info(f"{self.session_name} | {self.EMOJI['success']} Профиль обновлен после получения награды за рефералов. Гемов: {gems}")

        # ШАГ 3: Обычные бои (первые по приоритету)
        if settings.AUTO_BATTLE and unranked_energy > 0:
            logger.info(f"{self.session_name} | 🔄 Начинаем обычные бои")
            await self.process_battles(characters, "Unranked", unranked_energy)
            
            # Обновляем профиль после боев
            updated_profile = await self.get_profile()
            if updated_profile:
                unranked_energy = updated_profile.get('unranked_energy', 0)
                ranked_energy = updated_profile.get('ranked_energy', 0)
            
        # ШАГ 4: Рейтинговые бои
        if settings.AUTO_BATTLE and ranked_energy > 0:
            logger.info(f"{self.session_name} | ⚔️ Начинаем рейтинговые бои")
            await self.process_battles(characters, "Ranked", ranked_energy)
            
            # Обновляем профиль после боев
            updated_profile = await self.get_profile()
            if updated_profile:
                unranked_energy = updated_profile.get('unranked_energy', 0)
                ranked_energy = updated_profile.get('ranked_energy', 0)
                gems = updated_profile.get('gems', gems)
                has_claimable_activity = updated_profile.get('has_claimable_activity', False)
            
            # После боев проверяем на восстановление энергии
            if settings.AUTO_REFILL_ENERGY:
                # ВАЖНО: Получаем актуальный профиль для точного расчета гемов
                current_profile_for_refill = await self.get_profile()
                if not current_profile_for_refill:
                    logger.warning(f"{self.session_name} | {self.EMOJI['warning']} Не удалось получить актуальный профиль для рефилла")
                    current_profile_for_refill = updated_profile or profile
                
                energy_type = settings.REFILL_ENERGY_TYPE.lower()
                refilled_any = False
                
                if energy_type == "both":
                    # Восстанавливаем оба типа энергии
                    if unranked_energy == 0:
                        refill_success = await self.smart_energy_refill(current_profile_for_refill, "unranked")
                        if refill_success:
                            refilled_any = True
                    
                    if ranked_energy == 0:
                        refill_success = await self.smart_energy_refill(current_profile_for_refill, "ranked")
                        if refill_success:
                            refilled_any = True
                            
                elif energy_type in ["ranked", "unranked"]:
                    # Проверяем текущую энергию после боев
                    current_energy = unranked_energy if energy_type == "unranked" else ranked_energy
                    if current_energy == 0:  # Восстанавливаем только если энергия кончилась
                        refill_success = await self.smart_energy_refill(current_profile_for_refill, energy_type)
                        if refill_success:
                            refilled_any = True
                            
                # Если что-то восстановили - продолжаем бои
                if refilled_any:
                    # Обновляем профиль после восстановления
                    updated_profile_after_refill = await self.get_profile()
                    if updated_profile_after_refill:
                        logger.info(f"{self.session_name} | {self.EMOJI['success']} Энергия восстановлена! Продолжаем бои.")
                        return  # Возвращаемся к началу цикла для новых боев

        # ШАГ 5: Дополнительная проверка рефилла перед мутацией (если энергия равна 0)
        if settings.AUTO_REFILL_ENERGY:
            # Получаем актуальный профиль
            current_profile_check = await self.get_profile()
            if current_profile_check:
                current_unranked = current_profile_check.get('unranked_energy', 0)
                current_ranked = current_profile_check.get('ranked_energy', 0)
                
                # Если любая энергия равна 0 - пытаемся рефилл
                if current_unranked == 0 or current_ranked == 0:
                    energy_type = settings.REFILL_ENERGY_TYPE.lower()
                    refilled_any = False
                    
                    if energy_type == "both":
                        if current_unranked == 0:
                            refill_success = await self.smart_energy_refill(current_profile_check, "unranked")
                            if refill_success:
                                refilled_any = True
                        
                        if current_ranked == 0:
                            refill_success = await self.smart_energy_refill(current_profile_check, "ranked")
                            if refill_success:
                                refilled_any = True
                                
                    elif energy_type == "unranked" and current_unranked == 0:
                        refill_success = await self.smart_energy_refill(current_profile_check, "unranked")
                        if refill_success:
                            refilled_any = True
                            
                    elif energy_type == "ranked" and current_ranked == 0:
                        refill_success = await self.smart_energy_refill(current_profile_check, "ranked")
                        if refill_success:
                            refilled_any = True
                    
                    # Если рефилл прошел успешно - возвращаемся к началу цикла
                    if refilled_any:
                        logger.info(f"{self.session_name} | {self.EMOJI['success']} Энергия восстановлена перед мутацией! Продолжаем бои.")
                        return

        # ШАГ 6: Автоматическая мутация за гемы (только если остается запас гемов для следующего рефилла)
        if settings.AUTO_MUTATION:
            # Проверяем ограничение на количество мутаций за цикл
            if settings.MAX_MUTATIONS_PER_CYCLE > 0 and self._stats['mutations_performed'] >= settings.MAX_MUTATIONS_PER_CYCLE:
                logger.info(f"{self.session_name} | 🚫 Достигнут лимит мутаций за цикл: {self._stats['mutations_performed']}/{settings.MAX_MUTATIONS_PER_CYCLE}")
            else:
                # Получаем актуальный профиль для точного расчета гемов
                current_profile = await self.get_profile()
                if current_profile:
                    gems = current_profile.get('gems', gems)
                    unranked_energy = current_profile.get('unranked_energy', unranked_energy)
                    ranked_energy = current_profile.get('ranked_energy', ranked_energy)
                
                mutation_price = self._get_mutation_gems_price(current_profile or profile)

                # --- NEW LOGIC: Calculate safety margin for next refill ---
                # Приоритет: сохраняем гемы на следующий рефилл для любого типа энергии, который сейчас равен 0,
                # до достижения лимита settings.MAX_ENERGY_REFILLS.
                safety_margin = 0

                # 1. Safety for Ranked Refill
                if ranked_energy == 0 and self._stats['ranked_refills'] < settings.MAX_ENERGY_REFILLS:
                    next_ranked_cost = self.get_refill_cost(self._stats['ranked_refills'] + 1)
                    safety_margin = max(safety_margin, next_ranked_cost)

                # 2. Safety for Unranked Refill
                if unranked_energy == 0 and self._stats['unranked_refills'] < settings.MAX_ENERGY_REFILLS:
                    next_unranked_cost = self.get_refill_cost(self._stats['unranked_refills'] + 1)
                    # Берем максимальную стоимость из двух, чтобы покрыть наиболее дорогой необходимый рефилл.
                    safety_margin = max(safety_margin, next_unranked_cost)

                required_gems = mutation_price + safety_margin

                if mutation_price > 0 and gems >= required_gems:
                    remaining_mutations = settings.MAX_MUTATIONS_PER_CYCLE - self._stats['mutations_performed'] if settings.MAX_MUTATIONS_PER_CYCLE > 0 else "∞"
                    logger.info(f"{self.session_name} | 🧬 Выполняем мутацию за {mutation_price} гемов. Запас на рефилл: {safety_margin} гемов. Осталось мутаций: {remaining_mutations}")
                    mutation_result = await self.mutate_gems()
                    if mutation_result:
                        self._stats['mutations_performed'] += 1
                        char_name = mutation_result.get('name', 'Unknown')
                        char_rarity = mutation_result.get('rarity', 'Unknown')
                        logger.info(f"{self.session_name} | 🎉 Получен персонаж: {char_name} ({char_rarity}). Мутаций выполнено: {self._stats['mutations_performed']}")
                        # Обновляем список персонажей
                        characters = await self.get_characters() or characters
                        # Обновляем профиль после мутации
                        profile = await self.get_profile() or profile
                        gems = profile.get('gems', 0) if profile else 0
                else:
                    if settings.DEBUG_LOGGING or mutation_price > 0:
                        if mutation_price > 0:
                            logger.info(f"{self.session_name} | 🚫 Отмена мутации: {gems} гемов < {required_gems} (цена {mutation_price} + запас {safety_margin})")
        
        # Получаем обновленный профиль после боев
        updated_profile = await self.get_profile()
        if updated_profile:
            unranked_energy = updated_profile.get('unranked_energy', 0)
            ranked_energy = updated_profile.get('ranked_energy', 0)
            next_unranked_energy_at = updated_profile.get('next_unranked_energy_at')
            next_ranked_energy_at = updated_profile.get('next_ranked_energy_at')
            logger.info(f"{self.session_name} | {self.EMOJI['info']} Обновленный профиль: обычная энергия {unranked_energy}, рейтинговая энергия {ranked_energy}")
        else:
            logger.warning(f"{self.session_name} | {self.EMOJI['warning']} Не удалось получить обновленный профиль")
        
        # Логируем состояние энергии после боев
        logger.debug(f"{self.session_name} | {self.EMOJI['info']} Состояние после боев: обычная энергия {unranked_energy}, рейтинговая энергия {ranked_energy}")
        
        # Если есть любая энергия - продолжаем бои без сна
        if unranked_energy > 0 or ranked_energy > 0:
            logger.info(f"{self.session_name} | {self.EMOJI['energy']} Энергия доступна! Обычная: {unranked_energy}, Рейтинговая: {ranked_energy}. Продолжаем бои!")
            return  # Возвращаемся к началу цикла без сна
        
        # Рассчитываем время сна на основе данных профиля
        # Преобразуем строки в int для timestamp
        next_unranked_timestamp = int(next_unranked_energy_at) if next_unranked_energy_at else 0
        next_ranked_timestamp = int(next_ranked_energy_at) if next_ranked_energy_at else 0
        
        sleep_duration = self.calculate_sleep_duration(
            unranked_energy, ranked_energy, 
            next_unranked_timestamp, next_ranked_timestamp
        )
        
        # Выводим статистику и ждем до восстановления энергии
        self.print_session_stats(sleep_duration)
        
        # Краткая информация о состоянии энергии
        logger.info(f"{self.session_name} | {self.EMOJI['info']} Нет энергии для боев, засыпаем до восстановления")
        
        await asyncio.sleep(sleep_duration)



async def run_tapper(tg_client: UniversalTelegramClient):
    # Запускаем MutantGiftsBot
    bot = MutantGiftsBot(tg_client=tg_client)
    try:
        await bot.run()
    except InvalidSession as e:
        logger.error(f"Invalid Session: {e}")
        raise
