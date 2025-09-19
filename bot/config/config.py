from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Dict, Tuple
from enum import Enum

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_ignore_empty=True)

    API_ID: int = None
    API_HASH: str = None
    GLOBAL_CONFIG_PATH: str = "TG_FARM"

    FIX_CERT: bool = False

    SESSION_START_DELAY: int = 360

    REF_ID: str = 'r_252453226'
    SESSIONS_PER_PROXY: int = 1
    USE_PROXY: bool = True
    DISABLE_PROXY_REPLACE: bool = False

    DEVICE_PARAMS: bool = False

    DEBUG_LOGGING: bool = False

    AUTO_UPDATE: bool = True
    CHECK_UPDATE_INTERVAL: int = 60
    BLACKLISTED_SESSIONS: str = ""

    # Автоматизация Mutant Gifts
    AUTO_MUTATION: bool = True
    AUTO_BATTLE: bool = True
    AUTO_UPGRADE: bool = True
    AUTO_DISENCHANT: bool = True
    MIN_COINS_BALANCE: int = 0
    
    # Настройки распыления карточек
    DISENCHANT_RARITIES: str = "Common,Uncommon"
    
    # Настройки восстановления энергии
    AUTO_REFILL_ENERGY: bool = True
    REFILL_ENERGY_TYPE: str = "ranked"  # "ranked", "unranked" или "both"
    MAX_ENERGY_REFILLS: int = 1  # Максимальное количество восстановлений

    @property
    def blacklisted_sessions(self) -> List[str]:
        return [s.strip() for s in self.BLACKLISTED_SESSIONS.split(',') if s.strip()]
    
    @property
    def disenchant_rarities(self) -> List[str]:
        return [r.strip() for r in self.DISENCHANT_RARITIES.split(',') if r.strip()]

settings = Settings()
