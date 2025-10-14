import json
import os
from datetime import datetime, timedelta
from typing import Dict, Optional
from bot.utils.logger import logger


class SessionManager:
    """Класс для управления состоянием сессии и отслеживания рефиллов энергии"""
    
    def __init__(self, session_name: str):
        self.session_name = session_name
        self.session_file = f"sessions/{session_name}_session.json"
        self._ensure_sessions_directory()
        self.data = self._load_session_data()
    
    def _ensure_sessions_directory(self) -> None:
        """Создает директорию sessions если её нет"""
        os.makedirs("sessions", exist_ok=True)
    
    def _load_session_data(self) -> Dict:
        """Загружает данные сессии из файла"""
        if not os.path.exists(self.session_file):
            return self._create_default_session_data()
        
        try:
            with open(self.session_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return data
        except Exception as e:
            logger.error(f"{self.session_name} | Ошибка загрузки данных сессии: {e}")
            return self._create_default_session_data()
    
    def _create_default_session_data(self) -> Dict:
        """Создает данные сессии по умолчанию"""
        return {
            'next_ranked_refill_cost': 60,
            'next_unranked_refill_cost': 60,
            'total_gems_spent_today': 0,
            'last_activity_check': None,
            'can_mutate': True
        }
    
    def save_session_data(self) -> None:
        """Сохраняет данные сессии в JSON файл"""
        try:
            with open(self.session_file, 'w', encoding='utf-8') as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"{self.session_name} | Ошибка сохранения данных сессии: {e}")
    
    def get_next_ranked_refill_cost(self) -> int:
        """Возвращает стоимость следующего рефилла рейтинговой энергии"""
        return self.data.get('next_ranked_refill_cost', 60)
    
    def get_next_unranked_refill_cost(self) -> int:
        """Возвращает стоимость следующего рефилла обычной энергии"""
        return self.data.get('next_unranked_refill_cost', 60)
    
    def update_refill_costs_from_profile(self, profile: Dict) -> None:
        """Обновляет стоимость рефилов из данных профиля API"""
        ranked_cost = profile.get('refill_price_ranked_gems')
        unranked_cost = profile.get('refill_price_unranked_gems')
        
        if ranked_cost is not None:
            self.data['next_ranked_refill_cost'] = ranked_cost
            
        if unranked_cost is not None:
            self.data['next_unranked_refill_cost'] = unranked_cost
            
        if ranked_cost is not None or unranked_cost is not None:
            self.save_session_data()
            logger.debug(f"{self.session_name} | Обновлены стоимости рефилов из API: ranked={ranked_cost}, unranked={unranked_cost}")
    
    def record_ranked_refill(self) -> None:
        """Записывает выполненный рефилл рейтинговой энергии"""
        current_cost = self.get_next_ranked_refill_cost()
        self.data['total_gems_spent_today'] += current_cost
        self.save_session_data()
        logger.info(f"{self.session_name} | 💰 Рефилл рейтинговой энергии: {current_cost} гемов")
    
    def record_unranked_refill(self) -> None:
        """Записывает выполненный рефилл обычной энергии"""
        current_cost = self.get_next_unranked_refill_cost()
        self.data['total_gems_spent_today'] += current_cost
        self.save_session_data()
        logger.info(f"{self.session_name} | 💰 Рефилл обычной энергии: {current_cost} гемов")
    
    def can_afford_next_ranked_refill(self, current_gems: int) -> bool:
        """Проверяет, достаточно ли гемов для следующего рефилла рейтинговой энергии"""
        return current_gems >= self.get_next_ranked_refill_cost()
    
    def can_afford_next_unranked_refill(self, current_gems: int) -> bool:
        """Проверяет, достаточно ли гемов для следующего рефилла обычной энергии"""
        return current_gems >= self.get_next_unranked_refill_cost()
    
    def get_gems_needed_for_next_ranked_refill(self, current_gems: int) -> int:
        """Возвращает количество гемов, необходимых для следующего рефилла рейтинговой энергии"""
        cost = self.get_next_ranked_refill_cost()
        return max(0, cost - current_gems)
    
    def set_mutation_available(self, available: bool) -> None:
        """Устанавливает доступность мутации"""
        self.data['can_mutate'] = available
        self.save_session_data()
    
    def can_mutate_now(self) -> bool:
        """Проверяет, доступна ли мутация в данный момент"""
        return self.data.get('can_mutate', True)
    
    def update_activity_check_time(self) -> None:
        """Обновляет время последней проверки активностей"""
        self.data['last_activity_check'] = datetime.now().isoformat()
        self.save_session_data()
    
    def get_session_stats(self) -> Dict:
        """Возвращает статистику сессии"""
        return {
            'total_gems_spent_today': self.data.get('total_gems_spent_today', 0),
            'next_ranked_refill_cost': self.get_next_ranked_refill_cost(),
            'next_unranked_refill_cost': self.get_next_unranked_refill_cost()
        }