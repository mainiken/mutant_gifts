import os
import shutil
import glob
from datetime import datetime
from typing import Optional, List
from bot.utils.logger import logger


class SessionBackupManager:
    
    def __init__(self, sessions_path: str):
        self.sessions_path = sessions_path
        self.backup_dir = os.path.join(sessions_path, 'backups')
        os.makedirs(self.backup_dir, exist_ok=True)
    
    def get_session_file_path(self, session_name: str) -> Optional[str]:
        patterns = [
            os.path.join(self.sessions_path, f"{session_name}.session"),
            os.path.join(self.sessions_path, "telethon", f"{session_name}.session"),
            os.path.join(self.sessions_path, "pyrogram", f"{session_name}.session")
        ]
        
        for pattern in patterns:
            if os.path.exists(pattern):
                return pattern
        
        return None
    
    def create_backup(self, session_name: str) -> bool:
        session_file = self.get_session_file_path(session_name)
        if not session_file or not os.path.exists(session_file):
            logger.warning(f"Файл сессии {session_name} не найден для бэкапа")
            return False
        
        relative_path = os.path.relpath(os.path.dirname(session_file), self.sessions_path)
        if relative_path == ".":
            backup_subdir = self.backup_dir
        else:
            backup_subdir = os.path.join(self.backup_dir, relative_path)
        
        os.makedirs(backup_subdir, exist_ok=True)
        
        backup_filename = f"{session_name}.session.backup"
        backup_path = os.path.join(backup_subdir, backup_filename)
        
        try:
            shutil.copy2(session_file, backup_path)
            logger.info(f"✅ Бэкап сессии {session_name} создан: {backup_path}")
            return True
        except Exception as e:
            logger.error(f"❌ Ошибка при создании бэкапа {session_name}: {e}")
            return False
    
    def restore_from_backup(self, session_name: str) -> bool:
        patterns = [
            os.path.join(self.backup_dir, f"{session_name}.session.backup"),
            os.path.join(self.backup_dir, "telethon", f"{session_name}.session.backup"),
            os.path.join(self.backup_dir, "pyrogram", f"{session_name}.session.backup")
        ]
        
        backup_file = None
        for pattern in patterns:
            if os.path.exists(pattern):
                backup_file = pattern
                break
        
        if not backup_file:
            logger.error(f"❌ Бэкап для сессии {session_name} не найден")
            return False
        
        relative_path = os.path.relpath(os.path.dirname(backup_file), self.backup_dir)
        if relative_path == ".":
            target_dir = self.sessions_path
        else:
            target_dir = os.path.join(self.sessions_path, relative_path)
        
        os.makedirs(target_dir, exist_ok=True)
        
        target_path = os.path.join(target_dir, f"{session_name}.session")
        
        try:
            shutil.copy2(backup_file, target_path)
            logger.info(f"✅ Сессия {session_name} восстановлена из бэкапа: {target_path}")
            return True
        except Exception as e:
            logger.error(f"❌ Ошибка при восстановлении сессии {session_name} из бэкапа: {e}")
            return False
    
    def backup_exists(self, session_name: str) -> bool:
        patterns = [
            os.path.join(self.backup_dir, f"{session_name}.session.backup"),
            os.path.join(self.backup_dir, "telethon", f"{session_name}.session.backup"),
            os.path.join(self.backup_dir, "pyrogram", f"{session_name}.session.backup")
        ]
        
        return any(os.path.exists(pattern) for pattern in patterns)
    
    def create_all_backups(self) -> int:
        session_patterns = [
            os.path.join(self.sessions_path, "*.session"),
            os.path.join(self.sessions_path, "telethon", "*.session"),
            os.path.join(self.sessions_path, "pyrogram", "*.session")
        ]
        
        backed_up_count = 0
        for pattern in session_patterns:
            for session_file in glob.glob(pattern):
                session_name = os.path.basename(session_file).replace('.session', '')
                if self.create_backup(session_name):
                    backed_up_count += 1
        
        return backed_up_count
    
    def clean_old_backups(self, keep_count: int = 5) -> None:
        pass
