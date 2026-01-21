import sys
import os
import json
import time
import secrets
import socket
import threading
from datetime import datetime, timedelta
import asyncio
import aiohttp
import ssl
import certifi
from collections import defaultdict
import select
import pyaudio
import numpy as np
import wave
import queue
import hashlib
import zipfile
import tempfile
import shutil
from pathlib import Path
import urllib.request
import subprocess
import re

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QLineEdit, QPushButton, QListWidget, QLabel, QFrame,
    QTabWidget, QDialog, QComboBox, QSlider, QCheckBox, QGroupBox,
    QProgressBar, QFileDialog, QMessageBox, QScrollArea,
    QSystemTrayIcon, QMenu, QInputDialog, QSplitter, QListWidgetItem,
    QTextBrowser, QToolBar, QStatusBar, QToolButton, QSpinBox,
    QColorDialog, QGridLayout, QStackedWidget, QRadioButton,
    QButtonGroup, QTableWidget, QTableWidgetItem, QHeaderView,
    QDialogButtonBox, QPlainTextEdit, QFormLayout, QSpacerItem,
    QSizePolicy, QTabBar
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread, QSize, QSettings, QUrl, QFileInfo, QDate, QPoint, QRect
from PyQt6.QtGui import QFont, QIcon, QPalette, QColor, QPixmap, QAction, QDesktopServices, QTextCharFormat, QTextCursor, QBrush, QPainter, QPen
from PyQt6.QtMultimedia import QMediaPlayer, QAudioOutput

# ============================================================================
# КОНСТАНТЫ И НАСТРОЙКИ СЕРВЕРА
# ============================================================================
SERVER_DOMAIN = "reduxgamedev.ru"
SERVER_PORTS = [8000, 8001, 443, 22]
WS_SERVER_URL = f"wss://{SERVER_DOMAIN}:8001"
HTTP_API_URL = f"https://{SERVER_DOMAIN}:8000"
APP_NAME = "GoidaPhone NT Server"
APP_VERSION = "1.8.0"
COMPANY_NAME = "Winora Company"
UPDATE_URL = f"https://{SERVER_DOMAIN}/updates/goidaphone.json"

# Папки для данных
DATA_DIR = Path.home() / ".goidaphone_nt_server"
THEMES_DIR = DATA_DIR / "themes"
SOUNDS_DIR = DATA_DIR / "sounds"
CACHE_DIR = DATA_DIR / "cache"
CHAT_HISTORY_DIR = DATA_DIR / "chats"
CALL_HISTORY_DIR = DATA_DIR / "calls"
FILES_DIR = DATA_DIR / "files"
AVATARS_DIR = DATA_DIR / "avatars"

for directory in [DATA_DIR, THEMES_DIR, SOUNDS_DIR, CACHE_DIR, CHAT_HISTORY_DIR, CALL_HISTORY_DIR, FILES_DIR, AVATARS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# ============================================================================
# РЕАЛЬНОЕ СЕРВЕРНОЕ СОЕДИНЕНИЕ
# ============================================================================
class ServerConnection(QThread):
    connection_status = pyqtSignal(bool, str)
    message_received = pyqtSignal(dict)
    user_list_updated = pyqtSignal(list)
    call_incoming = pyqtSignal(dict)
    file_transfer_request = pyqtSignal(dict)
    auth_complete = pyqtSignal(bool, str, dict)
    friend_request = pyqtSignal(dict)
    group_created = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.ws = None
        self.session = None
        self.user_id = None
        self.token = None
        self.running = False
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = 10
        self.ssl_context = None
        self.loop = None
        self.connected = False
        
    def create_ssl_context(self):
        self.ssl_context = ssl.create_default_context(cafile=certifi.where())
        self.ssl_context.check_hostname = True
        self.ssl_context.verify_mode = ssl.CERT_REQUIRED
        
    async def connect_to_server(self):
        """Подключение к WebSocket серверу через доступные порты"""
        self.create_ssl_context()
        
        for port in SERVER_PORTS:
            try:
                ws_url = f"wss://{SERVER_DOMAIN}:{port}/ws"
                print(f"Попытка подключения к {ws_url}")
                
                connector = aiohttp.TCPConnector(ssl=self.ssl_context)
                self.session = aiohttp.ClientSession(connector=connector)
                
                self.ws = await self.session.ws_connect(
                    ws_url,
                    heartbeat=30,
                    timeout=aiohttp.ClientTimeout(total=10, connect=5)
                )
                
                print(f"✓ Успешное подключение к порту {port}")
                self.connected = True
                self.reconnect_attempts = 0
                self.connection_status.emit(True, f"Подключено к порту {port}")
                return True
                
            except Exception as e:
                print(f"✗ Ошибка подключения к порту {port}: {e}")
                continue
        
        self.connected = False
        return False
    
    async def authenticate(self, username, password, user_tag=None):
        """Реальная аутентификация на сервере"""
        if not self.connected or not self.ws:
            self.auth_complete.emit(False, "Нет соединения с сервером", {})
            return
            
        try:
            auth_data = {
                "action": "auth",
                "username": username,
                "password": password,
                "version": APP_VERSION,
                "client_type": "desktop"
            }
            if user_tag:
                auth_data["user_tag"] = user_tag
                
            await self.ws.send_json(auth_data)
            
            # Ждем ответа с таймаутом
            try:
                msg = await asyncio.wait_for(self.ws.receive(), timeout=10.0)
                
                if msg.type == aiohttp.WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    if data.get("status") == "success" and data.get("action") == "auth_response":
                        self.user_id = data["data"]["user_id"]
                        self.token = data["data"]["token"]
                        self.auth_complete.emit(True, "Успешная аутентификация", data["data"])
                    else:
                        self.auth_complete.emit(False, data.get("error", "Ошибка аутентификации"), {})
                else:
                    self.auth_complete.emit(False, "Некорректный ответ сервера", {})
                    
            except asyncio.TimeoutError:
                self.auth_complete.emit(False, "Таймаут аутентификации", {})
                
        except Exception as e:
            self.auth_complete.emit(False, f"Ошибка сети: {str(e)}", {})
    
    async def register(self, username, password, user_tag):
        """Реальная регистрация на сервере"""
        if not self.connected or not self.ws:
            self.auth_complete.emit(False, "Нет соединения с сервером", {})
            return
            
        try:
            reg_data = {
                "action": "register",
                "username": username,
                "password": password,
                "user_tag": user_tag,
                "version": APP_VERSION,
                "client_type": "desktop"
            }
            
            await self.ws.send_json(reg_data)
            
            try:
                msg = await asyncio.wait_for(self.ws.receive(), timeout=10.0)
                
                if msg.type == aiohttp.WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    if data.get("status") == "success" and data.get("action") == "register_response":
                        self.user_id = data["data"]["user_id"]
                        self.token = data["data"]["token"]
                        self.auth_complete.emit(True, "Успешная регистрация", data["data"])
                    else:
                        self.auth_complete.emit(False, data.get("error", "Ошибка регистрации"), {})
                else:
                    self.auth_complete.emit(False, "Некорректный ответ сервера", {})
                    
            except asyncio.TimeoutError:
                self.auth_complete.emit(False, "Таймаут регистрации", {})
                
        except Exception as e:
            self.auth_complete.emit(False, f"Ошибка сети: {str(e)}", {})
    
    async def listen_messages(self):
        """Прослушивание входящих сообщений"""
        while self.running and self.connected:
            try:
                msg = await self.ws.receive()
                
                if msg.type == aiohttp.WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    self.process_server_message(data)
                    
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    print(f"WebSocket ошибка: {self.ws.exception()}")
                    break
                    
                elif msg.type == aiohttp.WSMsgType.CLOSED:
                    print("Соединение закрыто сервером")
                    self.connected = False
                    self.connection_status.emit(False, "Соединение закрыто")
                    break
                    
            except Exception as e:
                print(f"Ошибка чтения сообщений: {e}")
                if self.running:
                    await self.reconnect()
                break
    
    def process_server_message(self, data):
        """Обработка сообщений от сервера"""
        action = data.get("action")
        
        if action == "user_list":
            self.user_list_updated.emit(data.get("users", []))
            
        elif action == "message":
            self.message_received.emit(data)
            
        elif action == "call_request":
            self.call_incoming.emit(data)
            
        elif action == "file_request":
            self.file_transfer_request.emit(data)
            
        elif action == "friend_request":
            self.friend_request.emit(data)
            
        elif action == "group_update":
            self.group_created.emit(data)
            
        elif action == "presence_update":
            # Обновление статуса пользователя
            pass
    
    async def send_message(self, content, message_type="public", target_id=None, group_id=None):
        """Отправка сообщения через сервер"""
        if not self.connected:
            return False
            
        try:
            msg_data = {
                "action": "send_message",
                "content": content,
                "message_type": message_type,
                "timestamp": int(time.time() * 1000)
            }
            
            if target_id:
                msg_data["target_id"] = target_id
            if group_id:
                msg_data["group_id"] = group_id
                
            await self.ws.send_json(msg_data)
            return True
            
        except Exception as e:
            print(f"Ошибка отправки сообщения: {e}")
            return False
    
    async def request_users(self):
        """Запрос списка пользователей"""
        if not self.connected:
            return False
            
        try:
            await self.ws.send_json({
                "action": "get_users"
            })
            return True
        except Exception as e:
            print(f"Ошибка запроса пользователей: {e}")
            return False
    
    async def initiate_call(self, target_id, call_type="voice", is_group=False):
        """Инициация звонка через сервер"""
        if not self.connected:
            return False
            
        try:
            await self.ws.send_json({
                "action": "initiate_call",
                "target_id": target_id,
                "call_type": call_type,
                "is_group": is_group
            })
            return True
        except Exception as e:
            print(f"Ошибка инициации звонка: {e}")
            return False
    
    async def send_file_metadata(self, target_id, filename, filesize, group_id=None):
        """Отправка метаданных файла через сервер"""
        if not self.connected:
            return None
            
        try:
            file_id = hashlib.md5(f"{self.user_id}_{filename}_{int(time.time())}".encode()).hexdigest()
            
            await self.ws.send_json({
                "action": "file_metadata",
                "file_id": file_id,
                "filename": filename,
                "filesize": filesize,
                "target_id": target_id,
                "group_id": group_id
            })
            return file_id
        except Exception as e:
            print(f"Ошибка отправки метаданных файла: {e}")
            return None
    
    async def add_friend(self, user_tag):
        """Добавление в друзья через сервер"""
        if not self.connected:
            return False
            
        try:
            await self.ws.send_json({
                "action": "add_friend",
                "user_tag": user_tag
            })
            return True
        except Exception as e:
            print(f"Ошибка добавления в друзья: {e}")
            return False
    
    async def create_group(self, name, members):
        """Создание группы через сервер"""
        if not self.connected:
            return False
            
        try:
            await self.ws.send_json({
                "action": "create_group",
                "name": name,
                "members": members
            })
            return True
        except Exception as e:
            print(f"Ошибка создания группы: {e}")
            return False
    
    async def update_presence(self, status="online", custom_status=None):
        """Обновление статуса присутствия"""
        if not self.connected:
            return False
            
        try:
            data = {
                "action": "update_presence",
                "status": status
            }
            if custom_status:
                data["custom_status"] = custom_status
                
            await self.ws.send_json(data)
            return True
        except Exception as e:
            print(f"Ошибка обновления статуса: {e}")
            return False
    
    async def reconnect(self):
        """Переподключение к серверу"""
        if self.reconnect_attempts >= self.max_reconnect_attempts:
            self.connection_status.emit(False, "Превышено количество попыток переподключения")
            return False
            
        self.reconnect_attempts += 1
        delay = min(60, 2 ** self.reconnect_attempts)
        
        print(f"Переподключение #{self.reconnect_attempts} через {delay} сек")
        await asyncio.sleep(delay)
        
        try:
            if await self.connect_to_server():
                if self.token:
                    # Повторная аутентификация
                    await self.ws.send_json({
                        "action": "reconnect_auth",
                        "user_id": self.user_id,
                        "token": self.token
                    })
                return True
            return False
        except Exception as e:
            print(f"Ошибка переподключения: {e}")
            return await self.reconnect()
    
    def run(self):
        """Основной поток соединения с сервером"""
        self.running = True
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        
        try:
            self.loop.run_until_complete(self.main_loop())
        except Exception as e:
            print(f"Ошибка в основном цикле: {e}")
        finally:
            self.loop.close()
    
    async def main_loop(self):
        """Главный асинхронный цикл"""
        if await self.connect_to_server():
            await self.listen_messages()
        else:
            self.connection_status.emit(False, "Не удалось подключиться к серверу")
    
    def stop(self):
        """Остановка соединения"""
        self.running = False
        if self.loop and self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)

# ============================================================================
# ДИАЛОГ ПОДКЛЮЧЕНИЯ К СЕРВЕРУ (ONLY ONLINE)
# ============================================================================
class ServerConnectionDialog(QDialog):
    connection_complete = pyqtSignal(bool, str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Подключение к ReduxNET")
        self.setModal(True)
        self.resize(500, 250)
        self.server_connection = ServerConnection()
        self.setup_ui()
        self.start_connection()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Заголовок
        title = QLabel("GoidaPhone NT Server 1.8")
        title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Статус
        self.status_label = QLabel("Подключение к сети ReduxNET...")
        self.status_label.setFont(QFont("Arial", 11))
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status_label)
        
        # Прогресс
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        layout.addWidget(self.progress_bar)
        
        # Детали
        self.details_label = QLabel("")
        self.details_label.setWordWrap(True)
        self.details_label.setStyleSheet("color: #888; font-size: 10px;")
        layout.addWidget(self.details_label)
        
        # Диагностика
        self.diagnostic_label = QLabel("")
        self.diagnostic_label.setWordWrap(True)
        self.diagnostic_label.setStyleSheet("color: #666; font-size: 9px;")
        layout.addWidget(self.diagnostic_label)
        
        # Кнопки
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        self.retry_button = QPushButton("Повторить")
        self.retry_button.clicked.connect(self.retry_connection)
        self.retry_button.setVisible(False)
        button_layout.addWidget(self.retry_button)
        
        self.cancel_button = QPushButton("Отмена")
        self.cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_button)
        
        layout.addLayout(button_layout)
        
        # Подключаем сигналы сервера
        self.server_connection.connection_status.connect(self.on_connection_status)
    
    def start_connection(self):
        """Начинаем подключение к серверу"""
        self.server_connection.start()
        self.connection_timeout = QTimer()
        self.connection_timeout.setSingleShot(True)
        self.connection_timeout.timeout.connect(self.on_connection_timeout)
        self.connection_timeout.start(30000)  # 30 секунд таймаут
    
    def on_connection_status(self, connected, message):
        """Обработка статуса подключения"""
        if connected:
            self.connection_timeout.stop()
            self.status_label.setText("✓ Успешно подключено к ReduxNET")
            self.status_label.setStyleSheet("color: green;")
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(100)
            self.details_label.setText(f"Сервер: {SERVER_DOMAIN}")
            
            QTimer.singleShot(1000, lambda: self.connection_complete.emit(True, message))
            QTimer.singleShot(1500, self.accept)
        else:
            self.status_label.setText("✗ Не удалось подключиться к ReduxNET")
            self.status_label.setStyleSheet("color: red;")
            self.details_label.setText(message)
            self.run_diagnostics()
            self.retry_button.setVisible(True)
    
    def on_connection_timeout(self):
        """Таймаут подключения"""
        self.status_label.setText("✗ Таймаут подключения")
        self.status_label.setStyleSheet("color: red;")
        self.details_label.setText("Сервер не отвечает в течение 30 секунд")
        self.run_diagnostics()
        self.retry_button.setVisible(True)
        self.server_connection.stop()
    
    def run_diagnostics(self):
        """Запуск диагностики проблемы"""
        self.diagnostic_label.setText("GoidaPhone определяет проблему...")
        
        # Тестируем доступность портов
        diagnostics = []
        
        for port in SERVER_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((SERVER_DOMAIN, port))
                sock.close()
                
                if result == 0:
                    diagnostics.append(f"Порт {port}: ✓ открыт")
                else:
                    diagnostics.append(f"Порт {port}: ✗ закрыт")
            except:
                diagnostics.append(f"Порт {port}: ✗ ошибка проверки")
        
        # Проверяем DNS
        try:
            socket.gethostbyname(SERVER_DOMAIN)
            diagnostics.append("DNS: ✓ разрешается")
        except:
            diagnostics.append("DNS: ✗ не разрешается")
        
        # Проверяем интернет
        try:
            socket.gethostbyname("google.com")
            diagnostics.append("Интернет: ✓ доступен")
            
            # Если интернет есть, но сервер недоступен - проблема на стороне Winora
            problem_location = "стороне Winora (сервер недоступен)"
        except:
            diagnostics.append("Интернет: ✗ недоступен")
            problem_location = "вашем ПК (нет интернет-соединения)"
        
        self.diagnostic_label.setText(f"Диагностика:\n" + "\n".join(diagnostics) + 
                                     f"\n\nGoidaPhone определяет проблему на {problem_location}")
    
    def retry_connection(self):
        """Повторная попытка подключения"""
        self.status_label.setText("Повторное подключение к ReduxNET...")
        self.status_label.setStyleSheet("")
        self.progress_bar.setRange(0, 0)
        self.details_label.setText("")
        self.diagnostic_label.setText("")
        self.retry_button.setVisible(False)
        
        self.server_connection.stop()
        time.sleep(1)
        self.server_connection = ServerConnection()
        self.server_connection.connection_status.connect(self.on_connection_status)
        self.start_connection()
    
    def closeEvent(self, event):
        self.server_connection.stop()
        super().closeEvent(event)

# ============================================================================
# РЕАЛЬНЫЙ ДИАЛОГ ВХОДА/РЕГИСТРАЦИИ (ONLY ONLINE)
# ============================================================================
class OnlineLoginDialog(QDialog):
    login_success = pyqtSignal(str, str, str, str, dict)
    register_success = pyqtSignal(str, str, str, str, dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.server_connection = None
        self.setWindowTitle("Вход / Регистрация - ReduxNET")
        self.setModal(True)
        self.resize(500, 400)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Заголовок
        title = QLabel("GoidaPhone NT Server 1.8")
        title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        subtitle = QLabel("Только онлайн-режим через ReduxNET")
        subtitle.setFont(QFont("Arial", 10))
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("color: #666;")
        layout.addWidget(subtitle)
        
        self.stacked_widget = QStackedWidget()
        
        # Страница входа
        self.login_page = self.create_login_page()
        self.stacked_widget.addWidget(self.login_page)
        
        # Страница регистрации
        self.register_page = self.create_register_page()
        self.stacked_widget.addWidget(self.register_page)
        
        layout.addWidget(self.stacked_widget)
        
        # Переключатель
        switch_layout = QHBoxLayout()
        switch_layout.addStretch()
        
        self.switch_button = QPushButton("Создать новый аккаунт")
        self.switch_button.clicked.connect(self.switch_pages)
        switch_layout.addWidget(self.switch_button)
        
        switch_layout.addStretch()
        layout.addLayout(switch_layout)
        
        # Статус
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: gray; font-size: 10px;")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status_label)
        
        # Инициализируем соединение
        self.init_server_connection()
    
    def init_server_connection(self):
        """Инициализация соединения с сервером"""
        self.server_connection = ServerConnection()
        self.server_connection.connection_status.connect(self.on_connection_status)
        self.server_connection.auth_complete.connect(self.on_auth_complete)
        self.server_connection.start()
    
    def on_connection_status(self, connected, message):
        """Обновление статуса подключения"""
        if connected:
            self.status_label.setText("✓ Подключено к серверу")
            self.status_label.setStyleSheet("color: green; font-size: 10px;")
            self.enable_inputs(True)
        else:
            self.status_label.setText(f"✗ {message}")
            self.status_label.setStyleSheet("color: red; font-size: 10px;")
            self.enable_inputs(False)
    
    def enable_inputs(self, enabled):
        """Включение/отключение полей ввода"""
        for widget in [self.login_username, self.login_password, 
                      self.register_username, self.register_password,
                      self.register_confirm, self.register_tag]:
            widget.setEnabled(enabled)
    
    def create_login_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(15)
        
        title = QLabel("Вход в аккаунт ReduxNET")
        title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Поля ввода
        form_layout = QFormLayout()
        form_layout.setSpacing(10)
        
        self.login_username = QLineEdit()
        self.login_username.setPlaceholderText("Имя пользователя или тег")
        form_layout.addRow("Логин:", self.login_username)
        
        self.login_password = QLineEdit()
        self.login_password.setPlaceholderText("Пароль")
        self.login_password.setEchoMode(QLineEdit.EchoMode.Password)
        form_layout.addRow("Пароль:", self.login_password)
        
        layout.addLayout(form_layout)
        
        # Кнопка входа
        self.login_button = QPushButton("Войти")
        self.login_button.clicked.connect(self.perform_login)
        self.login_button.setMinimumHeight(35)
        layout.addWidget(self.login_button)
        
        layout.addStretch()
        return page
    
    def create_register_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(15)
        
        title = QLabel("Регистрация в ReduxNET")
        title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Поля ввода
        form_layout = QFormLayout()
        form_layout.setSpacing(10)
        
        self.register_username = QLineEdit()
        self.register_username.setPlaceholderText("Только A-Z, a-z, 0-9, _, - (3-25 символов)")
        form_layout.addRow("Имя пользователя:", self.register_username)
        
        self.register_tag = QLineEdit()
        self.register_tag.setPlaceholderText("@username (3-25 символов после @)")
        form_layout.addRow("Уникальный тег:", self.register_tag)
        
        self.register_password = QLineEdit()
        self.register_password.setPlaceholderText("Минимум 6 символов")
        self.register_password.setEchoMode(QLineEdit.EchoMode.Password)
        form_layout.addRow("Пароль:", self.register_password)
        
        self.register_confirm = QLineEdit()
        self.register_confirm.setPlaceholderText("Повторите пароль")
        self.register_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        form_layout.addRow("Подтверждение:", self.register_confirm)
        
        layout.addLayout(form_layout)
        
        # Кнопка регистрации
        self.register_button = QPushButton("Зарегистрироваться")
        self.register_button.clicked.connect(self.perform_register)
        self.register_button.setMinimumHeight(35)
        layout.addWidget(self.register_button)
        
        layout.addStretch()
        return page
    
    def switch_pages(self):
        if self.stacked_widget.currentIndex() == 0:
            self.stacked_widget.setCurrentIndex(1)
            self.switch_button.setText("Войти в существующий аккаунт")
        else:
            self.stacked_widget.setCurrentIndex(0)
            self.switch_button.setText("Создать новый аккаунт")
    
    def validate_input(self, username, password, tag=None, confirm=None):
        """Валидация входных данных"""
        # Валидация имени пользователя
        if len(username) < 3 or len(username) > 25:
            return False, "Имя пользователя должно быть от 3 до 25 символов"
        
        if not re.match(r'^[A-Za-z0-9_-]+$', username):
            return False, "Имя пользователя может содержать только буквы A-Z, цифры, _ и -"
        
        # Валидация тега
        if tag:
            if not tag.startswith('@'):
                return False, "Тег должен начинаться с @"
            
            tag_content = tag[1:]
            if len(tag_content) < 3 or len(tag_content) > 25:
                return False, "Тег должен содержать от 3 до 25 символов после @"
            
            if not re.match(r'^[A-Za-z0-9_-]+$', tag_content):
                return False, "Тег может содержать только буквы A-Z, цифры, _ и -"
        
        # Валидация пароля
        if len(password) < 6:
            return False, "Пароль должен быть не менее 6 символов"
        
        if confirm and password != confirm:
            return False, "Пароли не совпадают"
        
        return True, ""
    
    def perform_login(self):
        """Выполнение входа"""
        username = self.login_username.text().strip()
        password = self.login_password.text()
        
        if not username or not password:
            QMessageBox.warning(self, "Ошибка", "Заполните все поля")
            return
        
        self.login_button.setEnabled(False)
        self.login_button.setText("Вход...")
        
        # Запускаем аутентификацию в отдельном потоке
        auth_thread = AuthThread(self.server_connection, "login", username, password)
        auth_thread.result.connect(self.on_auth_result)
        auth_thread.start()
    
    def perform_register(self):
        """Выполнение регистрации"""
        username = self.register_username.text().strip()
        password = self.register_password.text()
        confirm = self.register_confirm.text()
        tag = self.register_tag.text().strip()
        
        # Валидация
        valid, error = self.validate_input(username, password, tag, confirm)
        if not valid:
            QMessageBox.warning(self, "Ошибка", error)
            return
        
        self.register_button.setEnabled(False)
        self.register_button.setText("Регистрация...")
        
        # Запускаем регистрацию в отдельном потоке
        auth_thread = AuthThread(self.server_connection, "register", username, password, tag)
        auth_thread.result.connect(self.on_auth_result)
        auth_thread.start()
    
    def on_auth_result(self, success, action, message, user_data):
        """Результат аутентификации/регистрации"""
        if action == "login":
            self.login_button.setEnabled(True)
            self.login_button.setText("Войти")
        else:
            self.register_button.setEnabled(True)
            self.register_button.setText("Зарегистрироваться")
        
        if success:
            if action == "register":
                self.register_success.emit(
                    user_data['user_id'],
                    user_data['username'],
                    user_data['user_tag'],
                    user_data['token'],
                    user_data
                )
            else:
                self.login_success.emit(
                    user_data['user_id'],
                    user_data['username'],
                    user_data['user_tag'],
                    user_data['token'],
                    user_data
                )
            
            # Сохраняем учетные данные локально
            self.save_credentials(user_data)
            self.accept()
        else:
            QMessageBox.warning(self, "Ошибка", message)
    
    def save_credentials(self, user_data):
        """Сохранение учетных данных"""
        settings = QSettings("Winora Company", "GoidaPhone")
        
        saved_users = {}
        try:
            saved_users = json.loads(settings.value("saved_users", "{}"))
        except:
            pass
        
        saved_users[user_data['username']] = {
            'user_id': user_data['user_id'],
            'username': user_data['username'],
            'tag': user_data['user_tag'],
            'token': user_data['token'],
            'last_login': datetime.now().isoformat()
        }
        
        settings.setValue("saved_users", json.dumps(saved_users))
        settings.setValue("last_user", user_data['username'])
    
    def on_auth_complete(self, success, message, user_data):
        """Слот для сигнала от ServerConnection"""
        pass  # Обрабатывается в AuthThread
    
    def closeEvent(self, event):
        if self.server_connection:
            self.server_connection.stop()
        super().closeEvent(event)

class AuthThread(QThread):
    result = pyqtSignal(bool, str, str, dict)
    
    def __init__(self, server_connection, action, username, password, tag=None):
        super().__init__()
        self.server_connection = server_connection
        self.action = action
        self.username = username
        self.password = password
        self.tag = tag
    
    def run(self):
        if self.action == "login":
            future = asyncio.run_coroutine_threadsafe(
                self.server_connection.authenticate(self.username, self.password),
                self.server_connection.loop
            )
        else:
            future = asyncio.run_coroutine_threadsafe(
                self.server_connection.register(self.username, self.password, self.tag),
                self.server_connection.loop
            )
        
        try:
            # Ждем результат
            result = future.result(timeout=15)
            # Сигнал отправляется через server_connection.auth_complete
        except Exception as e:
            self.result.emit(False, self.action, f"Ошибка: {str(e)}", {})

# ============================================================================
# ОКНО ГРУППОВОГО ЗВОНКА (РЕАЛЬНОЕ ИСПОЛЬЗОВАНИЕ СЕРВЕРА)
# ============================================================================
class GroupCallWindow(QDialog):
    call_ended = pyqtSignal()
    
    def __init__(self, server_connection, call_data, parent=None):
        super().__init__(parent)
        self.server_connection = server_connection
        self.call_id = call_data.get("call_id")
        self.participants = call_data.get("participants", [])
        self.is_initiator = call_data.get("is_initiator", False)
        
        self.setWindowTitle(f"Групповой звонок - {len(self.participants)} участников")
        self.setMinimumSize(600, 500)
        self.setup_ui()
        self.start_call()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Заголовок
        title_layout = QHBoxLayout()
        title = QLabel("Групповой звонок")
        title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        title_layout.addWidget(title)
        
        self.timer_label = QLabel("00:00")
        self.timer_label.setFont(QFont("Arial", 12))
        title_layout.addWidget(self.timer_label)
        
        title_layout.addStretch()
        layout.addLayout(title_layout)
        
        # Список участников
        participants_group = QGroupBox("Участники")
        participants_layout = QVBoxLayout(participants_group)
        
        self.participants_table = QTableWidget()
        self.participants_table.setColumnCount(5)
        self.participants_table.setHorizontalHeaderLabels(["Имя", "Тег", "Статус", "Микрофон", "Премиум"])
        self.participants_table.horizontalHeader().setStretchLastSection(True)
        
        participants_layout.addWidget(self.participants_table)
        layout.addWidget(participants_group)
        
        # Статус звонка
        self.status_label = QLabel("Установка соединения...")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status_label)
        
        # Кнопки управления
        buttons_layout = QHBoxLayout()
        
        self.mic_button = QPushButton("🔇 Выкл микрофон")
        self.mic_button.setCheckable(True)
        self.mic_button.setChecked(False)
        self.mic_button.clicked.connect(self.toggle_microphone)
        buttons_layout.addWidget(self.mic_button)
        
        self.speaker_button = QPushButton("🔈 Выкл динамик")
        self.speaker_button.setCheckable(True)
        self.speaker_button.setChecked(False)
        self.speaker_button.clicked.connect(self.toggle_speaker)
        buttons_layout.addWidget(self.speaker_button)
        
        buttons_layout.addStretch()
        
        self.end_call_button = QPushButton("📞 Завершить звонок")
        self.end_call_button.setStyleSheet("background-color: #ff4444; color: white;")
        self.end_call_button.clicked.connect(self.end_call)
        buttons_layout.addWidget(self.end_call_button)
        
        layout.addLayout(buttons_layout)
        
        # Таймер
        self.call_timer = QTimer()
        self.call_timer.timeout.connect(self.update_timer)
        self.call_start_time = time.time()
    
    def start_call(self):
        """Начало группового звонка"""
        self.update_participants_list()
        self.call_timer.start(1000)
        self.status_label.setText("Звонок активен")
        
        # Уведомляем сервер о начале звонка
        asyncio.run_coroutine_threadsafe(
            self.server_connection.update_presence("in_call", "В групповом звонке"),
            self.server_connection.loop
        )
    
    def update_participants_list(self):
        """Обновление списка участников"""
        self.participants_table.setRowCount(len(self.participants))
        
        for i, participant in enumerate(self.participants):
            # Имя
            name_item = QTableWidgetItem(participant.get("username", "Unknown"))
            self.participants_table.setItem(i, 0, name_item)
            
            # Тег
            tag_item = QTableWidgetItem(participant.get("user_tag", "@unknown"))
            self.participants_table.setItem(i, 1, tag_item)
            
            # Статус
            status_item = QTableWidgetItem("✅ Подключен" if participant.get("connected", False) else "❌ Отключен")
            self.participants_table.setItem(i, 2, status_item)
            
            # Микрофон
            mic_status = "🔇" if participant.get("mic_muted", False) else "🎤"
            mic_item = QTableWidgetItem(mic_status)
            self.participants_table.setItem(i, 3, mic_item)
            
            # Премиум
            premium_status = "👑" if participant.get("premium", False) else "—"
            premium_item = QTableWidgetItem(premium_status)
            self.participants_table.setItem(i, 4, premium_item)
    
    def update_timer(self):
        """Обновление таймера звонка"""
        elapsed = int(time.time() - self.call_start_time)
        minutes = elapsed // 60
        seconds = elapsed % 60
        self.timer_label.setText(f"{minutes:02d}:{seconds:02d}")
    
    def toggle_microphone(self):
        muted = self.mic_button.isChecked()
        if muted:
            self.mic_button.setText("🎤 Вкл микрофон")
        else:
            self.mic_button.setText("🔇 Выкл микрофон")
    
    def toggle_speaker(self):
        muted = self.speaker_button.isChecked()
        if muted:
            self.speaker_button.setText("🔊 Вкл динамик")
        else:
            self.speaker_button.setText("🔈 Выкл динамик")
    
    def end_call(self):
        """Завершение звонка"""
        self.call_timer.stop()
        
        # Уведомляем сервер о завершении звонка
        asyncio.run_coroutine_threadsafe(
            self.server_connection.update_presence("online"),
            self.server_connection.loop
        )
        
        self.call_ended.emit()
        self.accept()
    
    def closeEvent(self, event):
        self.end_call()
        super().closeEvent(event)

# ============================================================================
# ВИДЖЕТ ДРУЗЕЙ С РЕАЛЬНЫМ СЕРВЕРОМ
# ============================================================================
class FriendsWidget(QWidget):
    friend_selected = pyqtSignal(dict)
    friend_request_received = pyqtSignal(dict)
    
    def __init__(self, server_connection):
        super().__init__()
        self.server_connection = server_connection
        self.friends = []
        self.pending_requests = []
        self.setup_ui()
        self.setup_server_signals()
        self.load_friends()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(5)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Заголовок
        title = QLabel("Друзья")
        title.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        layout.addWidget(title)
        
        # Поиск
        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Поиск друзей...")
        self.search_input.textChanged.connect(self.filter_friends)
        search_layout.addWidget(self.search_input)
        
        self.add_friend_button = QPushButton("Добавить")
        self.add_friend_button.clicked.connect(self.show_add_friend_dialog)
        search_layout.addWidget(self.add_friend_button)
        
        layout.addLayout(search_layout)
        
        # Вкладки
        self.tabs = QTabWidget()
        
        # Друзья онлайн
        self.friends_online_widget = QListWidget()
        self.friends_online_widget.itemClicked.connect(self.on_friend_selected)
        self.tabs.addTab(self.friends_online_widget, "Онлайн")
        
        # Все друзья
        self.friends_all_widget = QListWidget()
        self.friends_all_widget.itemClicked.connect(self.on_friend_selected)
        self.tabs.addTab(self.friends_all_widget, "Все")
        
        # Запросы в друзья
        self.requests_widget = QListWidget()
        self.tabs.addTab(self.requests_widget, "Запросы")
        
        layout.addWidget(self.tabs)
        
        # Статус
        self.status_label = QLabel("Загрузка...")
        layout.addWidget(self.status_label)
    
    def setup_server_signals(self):
        """Настройка сигналов от сервера"""
        self.server_connection.friend_request.connect(self.on_friend_request)
        self.server_connection.user_list_updated.connect(self.on_users_updated)
    
    def load_friends(self):
        """Загрузка списка друзей с сервера"""
        asyncio.run_coroutine_threadsafe(
            self.request_friends_list(),
            self.server_connection.loop
        )
    
    async def request_friends_list(self):
        """Запрос списка друзей"""
        try:
            await self.server_connection.ws.send_json({
                "action": "get_friends"
            })
        except Exception as e:
            print(f"Ошибка запроса друзей: {e}")
    
    def on_friend_request(self, data):
        """Обработка входящего запроса в друзья"""
        request_data = data.get("data", {})
        self.pending_requests.append(request_data)
        self.update_requests_list()
        
        # Сигнализируем о новом запросе
        self.friend_request_received.emit(request_data)
    
    def on_users_updated(self, users):
        """Обновление списка пользователей"""
        # Фильтруем друзей из общего списка
        self.friends = [user for user in users if user.get("is_friend", False)]
        self.update_friends_lists()
    
    def update_friends_lists(self):
        """Обновление списков друзей"""
        self.friends_online_widget.clear()
        self.friends_all_widget.clear()
        
        online_count = 0
        for friend in self.friends:
            # Все друзья
            item_text = f"{friend.get('username', 'Unknown')} {friend.get('user_tag', '')}"
            if friend.get("premium", False):
                item_text += " 👑"
            
            item_all = QListWidgetItem(item_text)
            item_all.setData(Qt.ItemDataRole.UserRole, friend)
            self.friends_all_widget.addItem(item_all)
            
            # Только онлайн
            if friend.get("status") == "online":
                item_online = QListWidgetItem(item_text)
                item_online.setData(Qt.ItemDataRole.UserRole, friend)
                self.friends_online_widget.addItem(item_online)
                online_count += 1
        
        self.status_label.setText(f"Друзей: {len(self.friends)} (Онлайн: {online_count})")
    
    def update_requests_list(self):
        """Обновление списка запросов"""
        self.requests_widget.clear()
        
        for request in self.pending_requests:
            item_text = f"{request.get('from_username', 'Unknown')} ({request.get('from_tag', '')})"
            item = QListWidgetItem(item_text)
            item.setData(Qt.ItemDataRole.UserRole, request)
            self.requests_widget.addItem(item)
    
    def filter_friends(self):
        """Фильтрация друзей по поиску"""
        search_text = self.search_input.text().lower()
        
        # Фильтруем онлайн друзей
        for i in range(self.friends_online_widget.count()):
            item = self.friends_online_widget.item(i)
            item.setHidden(search_text not in item.text().lower())
        
        # Фильтруем всех друзей
        for i in range(self.friends_all_widget.count()):
            item = self.friends_all_widget.item(i)
            item.setHidden(search_text not in item.text().lower())
    
    def on_friend_selected(self, item):
        """Выбор друга из списка"""
        friend_data = item.data(Qt.ItemDataRole.UserRole)
        if friend_data:
            self.friend_selected.emit(friend_data)
    
    def show_add_friend_dialog(self):
        """Диалог добавления друга"""
        dialog = AddFriendDialog(self.server_connection, self)
        dialog.friend_added.connect(self.on_friend_added)
        dialog.exec()
    
    def on_friend_added(self, success, message):
        """Результат добавления друга"""
        if success:
            QMessageBox.information(self, "Успех", message)
            self.load_friends()  # Перезагружаем список
        else:
            QMessageBox.warning(self, "Ошибка", message)

class AddFriendDialog(QDialog):
    friend_added = pyqtSignal(bool, str)
    
    def __init__(self, server_connection, parent=None):
        super().__init__(parent)
        self.server_connection = server_connection
        self.setWindowTitle("Добавить друга")
        self.setModal(True)
        self.resize(300, 150)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(15, 15, 15, 15)
        
        layout.addWidget(QLabel("Введите тег друга (начинается с @):"))
        
        self.tag_input = QLineEdit()
        self.tag_input.setPlaceholderText("@username")
        layout.addWidget(self.tag_input)
        
        buttons_layout = QHBoxLayout()
        buttons_layout.addStretch()
        
        cancel_button = QPushButton("Отмена")
        cancel_button.clicked.connect(self.reject)
        buttons_layout.addWidget(cancel_button)
        
        self.add_button = QPushButton("Добавить")
        self.add_button.clicked.connect(self.add_friend)
        buttons_layout.addWidget(self.add_button)
        
        layout.addLayout(buttons_layout)
        
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: gray; font-size: 10px;")
        layout.addWidget(self.status_label)
    
    def add_friend(self):
        tag = self.tag_input.text().strip()
        
        if not tag.startswith('@'):
            self.status_label.setText("Тег должен начинаться с @")
            self.status_label.setStyleSheet("color: red; font-size: 10px;")
            return
        
        self.add_button.setEnabled(False)
        self.status_label.setText("Отправка запроса...")
        
        # Отправляем запрос на сервер
        asyncio.run_coroutine_threadsafe(
            self.send_friend_request(tag),
            self.server_connection.loop
        )
    
    async def send_friend_request(self, tag):
        try:
            success = await self.server_connection.add_friend(tag)
            if success:
                self.friend_added.emit(True, f"Запрос дружбы отправлен {tag}")
                self.accept()
            else:
                self.friend_added.emit(False, f"Не удалось отправить запрос {tag}")
                self.add_button.setEnabled(True)
                self.status_label.setText("Ошибка отправки")
                self.status_label.setStyleSheet("color: red; font-size: 10px;")
        except Exception as e:
            self.friend_added.emit(False, f"Ошибка: {str(e)}")
            self.add_button.setEnabled(True)
            self.status_label.setText("Ошибка сети")
            self.status_label.setStyleSheet("color: red; font-size: 10px;")

# ============================================================================
# ГЛАВНОЕ ОКНО ПРИЛОЖЕНИЯ (ТОЛЬКО ОНЛАЙН)
# ============================================================================
class GoidaPhoneApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.user_id = ""
        self.username = ""
        self.user_tag = ""
        self.token = ""
        self.premium = False
        self.server_connection = None
        self.current_theme = "dark"
        
        self.setup_app()
        self.show_connection_dialog()
    
    def setup_app(self):
        self.setWindowTitle(f"{APP_NAME} {APP_VERSION} - {COMPANY_NAME}")
        self.setGeometry(100, 100, 1200, 800)
        self.setMinimumSize(1000, 700)
        
        # Центрируем окно
        screen_geometry = QApplication.primaryScreen().geometry()
        x = (screen_geometry.width() - self.width()) // 2
        y = (screen_geometry.height() - self.height()) // 2
        self.move(x, y)
    
    def show_connection_dialog(self):
        """Показываем диалог подключения к серверу"""
        dialog = ServerConnectionDialog(self)
        dialog.connection_complete.connect(self.on_connection_complete)
        dialog.exec()
    
    def on_connection_complete(self, connected, message):
        """Результат подключения к серверу"""
        if connected:
            self.show_login_dialog()
        else:
            QMessageBox.critical(self, "Ошибка", 
                               f"Не удалось подключиться к серверу.\n{message}\n\nПриложение будет закрыто.")
            QTimer.singleShot(1000, self.close)
    
    def show_login_dialog(self):
        """Показываем диалог входа/регистрации"""
        dialog = OnlineLoginDialog(self)
        dialog.login_success.connect(self.on_login_success)
        dialog.register_success.connect(self.on_register_success)
        
        if dialog.exec() != QDialog.DialogCode.Accepted:
            QMessageBox.warning(self, "Выход", "Требуется вход в систему.")
            self.close()
    
    def on_login_success(self, user_id, username, user_tag, token, user_data):
        """Успешный вход"""
        self.user_id = user_id
        self.username = username
        self.user_tag = user_tag
        self.token = token
        self.premium = user_data.get("premium", False)
        self.server_connection = dialog.server_connection
        
        self.setup_main_ui()
        self.setup_server_connection()
        self.show()
        
        # Сохраняем настройки
        self.save_user_settings(user_data)
    
    def on_register_success(self, user_id, username, user_tag, token, user_data):
        """Успешная регистрация"""
        self.on_login_success(user_id, username, user_tag, token, user_data)
    
    def setup_main_ui(self):
        """Настройка главного интерфейса"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Левая панель (200px)
        left_panel = QWidget()
        left_panel.setFixedWidth(200)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(5, 5, 5, 5)
        
        # Профиль пользователя
        profile_frame = QFrame()
        profile_frame.setFrameStyle(QFrame.Shape.StyledPanel)
        profile_layout = QVBoxLayout(profile_frame)
        
        self.avatar_label = QLabel()
        self.avatar_label.setFixedSize(64, 64)
        self.avatar_label.setStyleSheet("""
            border: 2px solid #444;
            border-radius: 32px;
            background-color: #333;
        """)
        profile_layout.addWidget(self.avatar_label, 0, Qt.AlignmentFlag.AlignCenter)
        
        self.username_label = QLabel(self.username)
        self.username_label.setFont(QFont("Arial", 11, QFont.Weight.Bold))
        self.username_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        profile_layout.addWidget(self.username_label)
        
        self.tag_label = QLabel(self.user_tag)
        self.tag_label.setStyleSheet("color: #888;")
        self.tag_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        profile_layout.addWidget(self.tag_label)
        
        if self.premium:
            premium_label = QLabel("👑 ПРЕМИУМ")
            premium_label.setStyleSheet("color: gold; font-weight: bold;")
            premium_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            profile_layout.addWidget(premium_label)
        
        left_layout.addWidget(profile_frame)
        
        # Кнопки навигации
        nav_buttons = [
            ("💬 Чаты", self.show_chats),
            ("👥 Друзья", self.show_friends),
            ("📞 Звонки", self.show_calls),
            ("⚙️ Настройки", self.show_settings)
        ]
        
        for text, callback in nav_buttons:
            btn = QPushButton(text)
            btn.setMinimumHeight(40)
            btn.clicked.connect(callback)
            left_layout.addWidget(btn)
        
        left_layout.addStretch()
        
        # Статус
        self.status_label = QLabel("🟢 Онлайн")
        self.status_label.setStyleSheet("color: green; font-size: 10px;")
        left_layout.addWidget(self.status_label)
        
        main_layout.addWidget(left_panel)
        
        # Центральная область
        self.central_stack = QStackedWidget()
        main_layout.addWidget(self.central_stack)
        
        # Инициализируем виджеты
        self.chats_widget = self.create_chats_widget()
        self.friends_widget = FriendsWidget(self.server_connection)
        self.calls_widget = self.create_calls_widget()
        self.settings_widget = self.create_settings_widget()
        
        self.central_stack.addWidget(self.chats_widget)
        self.central_stack.addWidget(self.friends_widget)
        self.central_stack.addWidget(self.calls_widget)
        self.central_stack.addWidget(self.settings_widget)
        
        # Статусбар
        self.setup_status_bar()
    
    def setup_server_connection(self):
        """Настройка соединения с сервером"""
        if self.server_connection:
            self.server_connection.message_received.connect(self.on_message_received)
            self.server_connection.call_incoming.connect(self.on_call_incoming)
            self.server_connection.file_transfer_request.connect(self.on_file_request)
            self.server_connection.user_list_updated.connect(self.on_user_list_updated)
            
            # Запрашиваем список пользователей
            asyncio.run_coroutine_threadsafe(
                self.server_connection.request_users(),
                self.server_connection.loop
            )
            
            # Устанавливаем статус онлайн
            asyncio.run_coroutine_threadsafe(
                self.server_connection.update_presence("online"),
                self.server_connection.loop
            )
    
    def setup_status_bar(self):
        status_bar = self.statusBar()
        
        # Статус подключения
        self.connection_status = QLabel("✓ Подключено")
        self.connection_status.setStyleSheet("color: green;")
        status_bar.addWidget(self.connection_status)
        
        status_bar.addPermanentWidget(QLabel(f"Пользователь: {self.user_tag}"))
        
        if self.premium:
            premium_status = QLabel("👑 Премиум")
            premium_status.setStyleSheet("color: gold;")
            status_bar.addPermanentWidget(premium_status)
    
    def create_chats_widget(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Заголовок
        title = QLabel("Чаты")
        title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        layout.addWidget(title)
        
        # Список чатов
        self.chats_list = QListWidget()
        layout.addWidget(self.chats_list)
        
        # Кнопка нового чата
        new_chat_btn = QPushButton("Новый чат")
        new_chat_btn.clicked.connect(self.create_new_chat)
        layout.addWidget(new_chat_btn)
        
        return widget
    
    def create_calls_widget(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        title = QLabel("Звонки")
        title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        layout.addWidget(title)
        
        # История звонков
        self.calls_history = QTableWidget()
        self.calls_history.setColumnCount(4)
        self.calls_history.setHorizontalHeaderLabels(["Тип", "Участники", "Время", "Длительность"])
        layout.addWidget(self.calls_history)
        
        # Кнопки звонков
        buttons_layout = QHBoxLayout()
        
        voice_call_btn = QPushButton("📞 Голосовой звонок")
        voice_call_btn.clicked.connect(self.start_voice_call)
        buttons_layout.addWidget(voice_call_btn)
        
        video_call_btn = QPushButton("🎥 Видеозвонок")
        video_call_btn.clicked.connect(self.start_video_call)
        buttons_layout.addWidget(video_call_btn)
        
        group_call_btn = QPushButton("👥 Групповой звонок")
        group_call_btn.clicked.connect(self.start_group_call)
        buttons_layout.addWidget(group_call_btn)
        
        layout.addLayout(buttons_layout)
        
        return widget
    
    def create_settings_widget(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        title = QLabel("Настройки")
        title.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        layout.addWidget(title)
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        
        settings_content = QWidget()
        settings_layout = QVBoxLayout(settings_content)
        
        # Настройки темы
        theme_group = QGroupBox("Тема оформления")
        theme_layout = QVBoxLayout(theme_group)
        
        theme_combo = QComboBox()
        theme_combo.addItems(["Тёмная", "Светлая", "Системная"])
        theme_combo.currentTextChanged.connect(self.change_theme)
        theme_layout.addWidget(theme_combo)
        
        settings_layout.addWidget(theme_group)
        
        # Настройки уведомлений
        notify_group = QGroupBox("Уведомления")
        notify_layout = QVBoxLayout(notify_group)
        
        self.notify_messages = QCheckBox("Сообщения")
        self.notify_messages.setChecked(True)
        notify_layout.addWidget(self.notify_messages)
        
        self.notify_calls = QCheckBox("Звонки")
        self.notify_calls.setChecked(True)
        notify_layout.addWidget(self.notify_calls)
        
        settings_layout.addWidget(notify_group)
        
        # Премиум функции
        if self.premium:
            premium_group = QGroupBox("Премиум функции")
            premium_layout = QVBoxLayout(premium_group)
            
            premium_layout.addWidget(QLabel("👑 Премиум активирован"))
            
            customize_btn = QPushButton("Настройка внешности")
            customize_btn.clicked.connect(self.show_premium_customization)
            premium_layout.addWidget(customize_btn)
            
            settings_layout.addWidget(premium_group)
        
        settings_layout.addStretch()
        
        scroll.setWidget(settings_content)
        layout.addWidget(scroll)
        
        return widget
    
    def show_chats(self):
        self.central_stack.setCurrentIndex(0)
    
    def show_friends(self):
        self.central_stack.setCurrentIndex(1)
    
    def show_calls(self):
        self.central_stack.setCurrentIndex(2)
    
    def show_settings(self):
        self.central_stack.setCurrentIndex(3)
    
    def on_message_received(self, data):
        """Обработка входящего сообщения"""
        message_data = data.get("data", {})
        sender = message_data.get("sender", {})
        content = message_data.get("content", "")
        
        # Показываем уведомление
        if self.notify_messages.isChecked():
            self.show_notification(f"Новое сообщение от {sender.get('username', 'Unknown')}", content)
    
    def on_call_incoming(self, data):
        """Входящий звонок"""
        call_data = data.get("data", {})
        caller = call_data.get("caller", {})
        call_type = call_data.get("type", "voice")
        
        reply = QMessageBox.question(self, "Входящий звонок",
                                   f"{caller.get('username', 'Unknown')} вызывает вас ({call_type})\n\nПринять?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            self.accept_call(call_data)
        else:
            self.decline_call(call_data)
    
    def on_file_request(self, data):
        """Запрос передачи файла"""
        file_data = data.get("data", {})
        sender = file_data.get("sender", {})
        filename = file_data.get("filename", "")
        filesize = file_data.get("filesize", 0)
        
        reply = QMessageBox.question(self, "Передача файла",
                                   f"{sender.get('username', 'Unknown')} отправляет файл:\n"
                                   f"{filename} ({self.format_size(filesize)})\n\nПринять?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            self.accept_file_transfer(file_data)
    
    def on_user_list_updated(self, users):
        """Обновление списка пользователей"""
        # Обновляем виджеты, которые используют список пользователей
        pass
    
    def show_notification(self, title, message):
        """Показать уведомление"""
        # Здесь должна быть реализация системных уведомлений
        pass
    
    def format_size(self, size):
        """Форматирование размера файла"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
    
    def accept_call(self, call_data):
        """Принять звонок"""
        # Реализация принятия звонка
        pass
    
    def decline_call(self, call_data):
        """Отклонить звонок"""
        # Реализация отклонения звонка
        pass
    
    def accept_file_transfer(self, file_data):
        """Принять передачу файла"""
        # Реализация приема файла
        pass
    
    def create_new_chat(self):
        """Создать новый чат"""
        # Реализация создания нового чата
        pass
    
    def start_voice_call(self):
        """Начать голосовой звонок"""
        # Реализация начала звонка
        pass
    
    def start_video_call(self):
        """Начать видеозвонок"""
        # Реализация видеозвонка
        pass
    
    def start_group_call(self):
        """Начать групповой звонок"""
        # Реализация группового звонка
        pass
    
    def change_theme(self, theme_name):
        """Смена темы оформления"""
        # Реализация смены темы
        pass
    
    def show_premium_customization(self):
        """Настройка премиум внешности"""
        # Реализация кастомизации для премиум
        pass
    
    def save_user_settings(self, user_data):
        """Сохранение настроек пользователя"""
        settings = QSettings("Winora Company", "GoidaPhone")
        settings.setValue("user_id", self.user_id)
        settings.setValue("username", self.username)
        settings.setValue("user_tag", self.user_tag)
        settings.setValue("token", self.token)
        settings.setValue("premium", self.premium)
        settings.setValue("last_login", datetime.now().isoformat())
    
    def closeEvent(self, event):
        """Обработка закрытия окна"""
        if self.server_connection:
            # Устанавливаем статус офлайн
            asyncio.run_coroutine_threadsafe(
                self.server_connection.update_presence("offline"),
                self.server_connection.loop
            )
            
            # Останавливаем соединение
            self.server_connection.stop()
        
        event.accept()

# ============================================================================
# ТОЧКА ВХОДА (ONLY ONLINE)
# ============================================================================
def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName(COMPANY_NAME)
    
    # Настройки по умолчанию
    app.setStyle("Fusion")
    
    try:
        window = GoidaPhoneApp()
        sys.exit(app.exec())
    except Exception as e:
        QMessageBox.critical(None, "Ошибка запуска", f"Не удалось запустить приложение:\n{str(e)}")
        return 1

if __name__ == "__main__":
    main()