import os
import shutil
import glob
import sqlite3
import time
from datetime import datetime
from typing import Optional, List
from pathlib import Path
from bot.utils.logger import logger


class SessionBackupManager:
    
    def __init__(self, sessions_path: str):
        self.sessions_path = sessions_path
        self.backup_dir = os.path.join(sessions_path, 'backups')
        os.makedirs(self.backup_dir, exist_ok=True)
    
    def _is_file_locked(self, file_path: str) -> bool:
        try:
            with open(file_path, 'a'):
                return False
        except (IOError, PermissionError):
            return True
    
    def _safe_sqlite_copy(self, source: str, destination: str) -> bool:
        max_retries = 3
        retry_delay = 1.0
        
        for attempt in range(max_retries):
            try:
                if self._is_file_locked(source):
                    logger.warning(
                        f"Файл {os.path.basename(source)} заблокирован, "
                        f"попытка {attempt + 1}/{max_retries}"
                    )
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay)
                        continue
                    return False
                
                conn = None
                try:
                    conn = sqlite3.connect(source, timeout=5.0)
                    conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                    conn.commit()
                except sqlite3.OperationalError as e:
                    logger.debug(
                        f"Не удалось выполнить CHECKPOINT для "
                        f"{os.path.basename(source)}: {e}"
                    )
                finally:
                    if conn:
                        conn.close()
                
                time.sleep(0.1)
                
                shutil.copy2(source, destination)
                
                wal_file = source + '-wal'
                if os.path.exists(wal_file):
                    try:
                        shutil.copy2(wal_file, destination + '-wal')
                    except Exception:
                        pass
                
                shm_file = source + '-shm'
                if os.path.exists(shm_file):
                    try:
                        shutil.copy2(shm_file, destination + '-shm')
                    except Exception:
                        pass
                
                return True
                
            except Exception as e:
                logger.error(
                    f"Ошибка при копировании {os.path.basename(source)}: {e}"
                )
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    continue
                return False
        
        return False
    
    def _verify_session_integrity(self, session_path: str) -> bool:
        if not os.path.exists(session_path):
            return False
        
        if os.path.getsize(session_path) < 1024:
            return False
        
        try:
            conn = sqlite3.connect(session_path, timeout=2.0)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            conn.close()
            
            if not tables:
                return False
            
            return True
        except Exception as e:
            logger.error(
                f"Ошибка проверки целостности "
                f"{os.path.basename(session_path)}: {e}"
            )
            return False
    
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
    
    def create_backup(self, session_name: str, use_timestamp: bool = True) -> bool:
        session_file = self.get_session_file_path(session_name)
        if not session_file or not os.path.exists(session_file):
            logger.warning(f"Файл сессии {session_name} не найден для бэкапа")
            return False
        
        if not self._verify_session_integrity(session_file):
            logger.warning(
                f"Сессия {session_name} повреждена или некорректна, "
                f"бэкап не создан"
            )
            return False
        
        relative_path = os.path.relpath(
            os.path.dirname(session_file), 
            self.sessions_path
        )
        if relative_path == ".":
            backup_subdir = self.backup_dir
        else:
            backup_subdir = os.path.join(self.backup_dir, relative_path)
        
        os.makedirs(backup_subdir, exist_ok=True)
        
        if use_timestamp:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_filename = f"{session_name}_{timestamp}.session.backup"
        else:
            backup_filename = f"{session_name}.session.backup"
        
        backup_path = os.path.join(backup_subdir, backup_filename)
        
        if self._safe_sqlite_copy(session_file, backup_path):
            logger.info(f"✅ Бэкап сессии {session_name} создан: {backup_path}")
            return True
        else:
            logger.error(f"❌ Ошибка при создании бэкапа {session_name}")
            return False
    
    def restore_from_backup(
        self, 
        session_name: str, 
        use_latest: bool = True
    ) -> bool:
        backup_dirs = [
            self.backup_dir,
            os.path.join(self.backup_dir, "telethon"),
            os.path.join(self.backup_dir, "pyrogram")
        ]
        
        all_backups = []
        for backup_dir in backup_dirs:
            if not os.path.exists(backup_dir):
                continue
            
            pattern = os.path.join(backup_dir, f"{session_name}*.session.backup")
            found_backups = glob.glob(pattern)
            all_backups.extend(found_backups)
        
        if not all_backups:
            logger.error(f"❌ Бэкап для сессии {session_name} не найден")
            return False
        
        if use_latest and len(all_backups) > 1:
            all_backups.sort(key=os.path.getmtime, reverse=True)
        
        for backup_file in all_backups:
            if not self._verify_session_integrity(backup_file):
                logger.warning(
                    f"Бэкап {os.path.basename(backup_file)} повреждён, "
                    f"пропускаем"
                )
                continue
            
            relative_path = os.path.relpath(
                os.path.dirname(backup_file), 
                self.backup_dir
            )
            if relative_path == ".":
                target_dir = self.sessions_path
            else:
                target_dir = os.path.join(self.sessions_path, relative_path)
            
            os.makedirs(target_dir, exist_ok=True)
            
            target_path = os.path.join(target_dir, f"{session_name}.session")
            
            if self._safe_sqlite_copy(backup_file, target_path):
                logger.info(
                    f"✅ Сессия {session_name} восстановлена из бэкапа: "
                    f"{target_path}"
                )
                return True
            else:
                logger.warning(
                    f"Не удалось восстановить из "
                    f"{os.path.basename(backup_file)}"
                )
        
        logger.error(
            f"❌ Не удалось восстановить сессию {session_name} "
            f"ни из одного бэкапа"
        )
        return False
    
    def backup_exists(self, session_name: str) -> bool:
        backup_dirs = [
            self.backup_dir,
            os.path.join(self.backup_dir, "telethon"),
            os.path.join(self.backup_dir, "pyrogram")
        ]
        
        for backup_dir in backup_dirs:
            if not os.path.exists(backup_dir):
                continue
            pattern = os.path.join(backup_dir, f"{session_name}*.session.backup")
            if glob.glob(pattern):
                return True
        
        return False
    
    def create_all_backups(self, auto_cleanup: bool = True) -> int:
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
        
        if auto_cleanup and backed_up_count > 0:
            self.clean_old_backups()
        
        return backed_up_count
    
    def clean_old_backups(self, keep_count: int = 5) -> int:
        backup_dirs = [
            self.backup_dir,
            os.path.join(self.backup_dir, "telethon"),
            os.path.join(self.backup_dir, "pyrogram")
        ]
        
        deleted_count = 0
        session_backups = {}
        
        for backup_dir in backup_dirs:
            if not os.path.exists(backup_dir):
                continue
            
            pattern = os.path.join(backup_dir, "*.session.backup")
            for backup_file in glob.glob(pattern):
                basename = os.path.basename(backup_file)
                
                parts = basename.rsplit('_', 1)
                if len(parts) == 2 and parts[1].replace('.session.backup', '').replace('_', '').isdigit():
                    session_name = parts[0]
                else:
                    session_name = basename.replace('.session.backup', '')
                
                if session_name not in session_backups:
                    session_backups[session_name] = []
                session_backups[session_name].append(backup_file)
        
        for session_name, backups in session_backups.items():
            if len(backups) <= keep_count:
                continue
            
            backups.sort(key=os.path.getmtime, reverse=True)
            
            for old_backup in backups[keep_count:]:
                try:
                    os.remove(old_backup)
                    
                    wal_file = old_backup + '-wal'
                    if os.path.exists(wal_file):
                        os.remove(wal_file)
                    
                    shm_file = old_backup + '-shm'
                    if os.path.exists(shm_file):
                        os.remove(shm_file)
                    
                    deleted_count += 1
                    logger.debug(
                        f"Удалён старый бэкап: {os.path.basename(old_backup)}"
                    )
                except Exception as e:
                    logger.error(
                        f"Ошибка при удалении бэкапа "
                        f"{os.path.basename(old_backup)}: {e}"
                    )
        
        if deleted_count > 0:
            logger.info(
                f"Очищено {deleted_count} старых бэкапов "
                f"(сохранено последних {keep_count} для каждой сессии)"
            )
        
        return deleted_count
