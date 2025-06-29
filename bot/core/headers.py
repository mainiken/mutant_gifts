from typing import Dict
from bot.core.agents import generate_random_user_agent

def get_agentx_headers(token: str) -> dict:
    return {
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
        "authorization": f"Bearer {token}",
    }

