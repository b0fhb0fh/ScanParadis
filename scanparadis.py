#!/usr/bin/python3

#
# ScanParadis v2.5 (with search_vulns)
#

import telebot
import subprocess
import re
from datetime import datetime
import json
import socket
import os, sys
import requests
import math
from telebot import util
from telebot.types import ReplyKeyboardMarkup, KeyboardButton, ReplyKeyboardRemove
from openai import OpenAI

# Загрузка конфигурации
try:
    with open("config.json", "r") as config_file:
        config = json.load(config_file)
except FileNotFoundError:
    print("Ошибка: файл config.json не найден.")
    sys.exit(1)
except json.JSONDecodeError:
    print("Ошибка: файл config.json имеет неверный формат.")
    sys.exit(1)

# Конфигурация (обязательные параметры)
TELEGRAM_BOT_TOKEN = config["TELEGRAM_BOT_TOKEN"]
ZAP_PATH = config.get("ZAP_PATH", "/opt/ZAP_2.16.1/zap-2.16.1.jar")
OPENAI_API_KEY = config.get("OPENAI_API_KEY", "")
OPENAI_BASE_URL = config.get("OPENAI_BASE_URL", "https://api.proxyapi.ru/deepseek")
OPENAI_MODEL = config.get("OPENAI_MODEL", "deepseek-chat")
SCAN_RESULTS_DIR = config.get("SCAN_RESULTS_DIR", "scanresults")
EPSS_API_URL = config.get("EPSS_API_URL", "https://api.first.org/data/v1/epss")
NVD_API_URL = config.get("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
EPSS_SIGNIFICANT_THRESHOLD = config.get("EPSS_SIGNIFICANT_THRESHOLD", 0.1)
NMAP_TIMEOUT = config.get("NMAP_TIMEOUT", 600)
ZAP_TIMEOUT = config.get("ZAP_TIMEOUT", 1800)
NUCLEI_TIMEOUT = config.get("NUCLEI_TIMEOUT", 1800)
ADVANCED_SCAN_TIMEOUT = config.get("ADVANCED_SCAN_TIMEOUT", 1200)
SOCKS5_PROXY = config.get("SOCKS5_PROXY", "socks5://127.0.0.1:9050")
HTTP_PROXY = config.get("HTTP_PROXY", "http://127.0.0.1:8118")
SEARCH_VULNS_SCRIPT = config.get("SEARCH_VULNS_SCRIPT", "/opt/search_vulns/search_vulns.py")
        

# Создаем директорию для результатов сканирования, если ее нет
os.makedirs(SCAN_RESULTS_DIR, exist_ok=True)

bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)

scan_target = ''
menu_state = {}  # Для отслеживания состояния меню пользователей

# Инициализация OpenAI клиента
ai_client = OpenAI(
    api_key=OPENAI_API_KEY,
    base_url=OPENAI_BASE_URL,
)

# Создаем главное меню
def create_main_menu():
    markup = ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
    
    btn1 = KeyboardButton('Recon 🕵️')
    btn2 = KeyboardButton('Scan 🔍')
    btn3 = KeyboardButton('Web 🌐')
    btn4 = KeyboardButton('Others 📚')
    btn5 = KeyboardButton('/help')
    
    markup.add(btn1, btn2, btn3, btn4, btn5)
    return markup

# Меню Recon
def create_recon_menu():
    markup = ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
    
    btn1 = KeyboardButton('nslookup')
    btn2 = KeyboardButton('whois')
    btn3 = KeyboardButton('subfinder')
    btn4 = KeyboardButton('Назад ↩️')
    
    markup.add(btn1, btn2, btn3, btn4)
    return markup

# Меню Scan
def create_scan_menu():
    markup = ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
    
    btn1 = KeyboardButton('IPv4scan')
    btn2 = KeyboardButton('IPv6scan')
    btn3 = KeyboardButton('Vulners')
    btn4 = KeyboardButton('Назад ↩️')
    
    markup.add(btn1, btn2, btn3, btn4)
    return markup

# Меню Web
def create_web_menu():
    markup = ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
    
    btn1 = KeyboardButton('wafcheck + tor')
    btn2 = KeyboardButton('whatweb')
    btn3 = KeyboardButton('ZAP')
    btn4 = KeyboardButton('Nuclei + tor')  
    btn5 = KeyboardButton('Назад ↩️')
    
    markup.add(btn1, btn2, btn3, btn4, btn5)
    return markup

# Меню Others
def create_others_menu():
    markup = ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
    
    btn1 = KeyboardButton('creds')
    btn2 = KeyboardButton('search_vulns')  # Новая кнопка
    btn3 = KeyboardButton('Назад ↩️')
    
    markup.add(btn1, btn2, btn3)
    return markup

@bot.message_handler(commands=['start', 'help'])
def handle_start(message):
    menu_state[message.chat.id] = 'main'
    bot.send_message(message.chat.id, "Бот предназначен исключительно для легальных проверок", 
                    reply_markup=create_main_menu())
    print_help(message)

@bot.message_handler(func=lambda message: True)
def handle_all_messages(message):
    chat_id = message.chat.id
    
    # Обработка главного меню
    if message.text == 'Recon 🕵️':
        menu_state[chat_id] = 'recon'
        bot.send_message(chat_id, "Выберите инструмент разведки:", reply_markup=create_recon_menu())
    elif message.text == 'Scan 🔍':
        menu_state[chat_id] = 'scan'
        bot.send_message(chat_id, "Выберите тип сканирования:", reply_markup=create_scan_menu())
    elif message.text == 'Web 🌐':
        menu_state[chat_id] = 'web'
        bot.send_message(chat_id, "Выберите веб-инструмент:", reply_markup=create_web_menu())
    elif message.text == 'Others 📚':
        menu_state[chat_id] = 'others'
        bot.send_message(chat_id, "Другие инструменты:", reply_markup=create_others_menu())
    elif message.text == 'Назад ↩️':
        menu_state[chat_id] = 'main'
        bot.send_message(chat_id, "Главное меню:", reply_markup=create_main_menu())
    
    # Обработка подменю Recon
    elif menu_state.get(chat_id) == 'recon':
        if message.text == 'nslookup':
            bot.send_message(chat_id, "Укажите доменное имя в формате host.example.com", 
                            reply_markup=ReplyKeyboardRemove())
            bot.register_next_step_handler(message, get_target_and_run, "nslookup")
        elif message.text == 'whois':
            bot.send_message(chat_id, "Укажите ip-адрес в формате 1.1.1.1 или 2a00:1450:4026:804::2004", 
                            reply_markup=ReplyKeyboardRemove())
            bot.register_next_step_handler(message, get_target_and_run, "whois")
        elif message.text == 'subfinder':
            bot.send_message(chat_id, "Укажите доменное имя в формате example.com", 
                            reply_markup=ReplyKeyboardRemove())
            bot.register_next_step_handler(message, get_target_and_run, "subfinder")
    
    # Обработка подменю Scan
    elif menu_state.get(chat_id) == 'scan':
        if message.text == 'IPv4scan':
            bot.send_message(chat_id, "Укажите один IPv4 адрес или одно доменное имя в формате 1.1.1.1 или www.example.com", 
                            reply_markup=ReplyKeyboardRemove())
            bot.register_next_step_handler(message, get_target_and_run, "nmap4")
        elif message.text == 'IPv6scan':
            bot.send_message(chat_id, "Укажите один IPv6 адрес или одно доменное имя в формате 2a00:1450:4026:804::2004 или www.example.com", 
                            reply_markup=ReplyKeyboardRemove())
            bot.register_next_step_handler(message, get_target_and_run, "nmap6")
        elif message.text == 'Vulners':
            bot.send_message(chat_id, "Укажите IP-адрес или домен для сканирования уязвимостей", 
                            reply_markup=ReplyKeyboardRemove())
            bot.register_next_step_handler(message, get_target_and_run, "vulners")
    
    # Обработка подменю Web
    elif menu_state.get(chat_id) == 'web':
        if message.text == 'wafcheck + tor':
            bot.send_message(chat_id, "Укажите url в формате https://www.example.com", 
                            reply_markup=ReplyKeyboardRemove())
            bot.register_next_step_handler(message, get_target_and_run, "wafw00f")
        elif message.text == 'whatweb':
            bot.send_message(chat_id, "Укажите url в формате https://www.example.com", 
                            reply_markup=ReplyKeyboardRemove())
            bot.register_next_step_handler(message, get_target_and_run, "whatweb")
        elif message.text == 'ZAP':
            bot.send_message(chat_id, "Укажите url в формате https://www.example.com для сканирования ZAP", 
                            reply_markup=ReplyKeyboardRemove())
            bot.register_next_step_handler(message, get_target_and_run, "zap")
        elif message.text == 'Nuclei + tor':
            bot.send_message(chat_id, "Укажите URL для сканирования Nuclei (например: https://example.com)", 
                            reply_markup=ReplyKeyboardRemove())
            bot.register_next_step_handler(message, get_target_and_run, "nuclei")

    # Обработка подменю Others
    elif menu_state.get(chat_id) == 'others':
        if message.text == 'creds':
            bot.send_message(chat_id, "Укажите наименование вендора или ПО", 
                            reply_markup=ReplyKeyboardRemove())
            bot.register_next_step_handler(message, get_target_and_run, "creds")
        elif message.text == 'search_vulns':  # Новый обработчик
            bot.send_message(chat_id, "Укажите название ПО и версию (например: Apache 2.4.55)", 
                        reply_markup=ReplyKeyboardRemove())
            bot.register_next_step_handler(message, get_target_and_run, "search_vulns")
    
    # Обработка команды /help
    elif message.text == '/help':
        print_help(message)
    
    else:
        bot.send_message(chat_id, "Команда не распознана. Попробуйте /help.", 
                        reply_markup=create_main_menu())

def get_target_and_run(message, proc="nslookup"):
    global scan_target
    # remove RCE tail and network mask  
    scan_target = message.text.strip().split(";")[0].split("|")[0].split("&")[0]

    if (check_target_ip_or_domain(scan_target) or check_target_url(scan_target) or proc == "creds" or proc == "search_vulns"):
        run_utils(message, proc)
    else:
        bot.send_message(message.chat.id, "Указан некорректный адрес. Попробуйте еще раз.", 
                        reply_markup=create_main_menu())
        print_help(message)

def run_utils(message, proc):
    bot.send_message(message.chat.id, "Придется немного подождать...")
    
    if proc == "zap":
        run_zap_scan(message)
        return
    elif proc == "nuclei":  
        run_nuclei_scan(message)
        return
    elif proc == "vulners":
        run_vulners_scan(message)
        return
    elif proc == "search_vulns":  
        run_search_vulns(message)
        return
    
    commands = {
        "nmap4": ["/usr/bin/nmap", "-sS", "-F", scan_target],
        "nmap6": ["/usr/bin/nmap", "-sS", "-F", "-6", scan_target],
        "wafw00f": ["wafw00f", "-p", SOCKS5_PROXY,  "-a", scan_target],
        "whatweb": ["whatweb", "--color=never", scan_target],
        "nslookup": ["host", scan_target],
        "whois": ["whois", scan_target],
        "subfinder": ["subfinder", "-silent", "-nc", "-d", scan_target],
        "creds": ["/opt/DefaultCreds-cheat-sheet/creds", "search", scan_target]
    }
    
    scan_result = subprocess.Popen(commands[proc], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    scan_output, scan_error = scan_result.communicate()
    scan_result.wait()
    
    # Find the relevant part of output for some commands
    i = 0
    if proc in ["nmap4", "nmap6"]:
        i = scan_output.find('Nmap scan')
    elif proc == "wafw00f":
        i = scan_output.find('Checking')
    
    splitted_text = util.smart_split(scan_output[i:], chars_per_string=3000)
    for text in splitted_text:
        bot.send_message(message.chat.id, text)

    print_log(message, scan_output)
    menu_state[message.chat.id] = 'main'
    bot.send_message(message.chat.id, "Выберите следующий инструмент:", reply_markup=create_main_menu())

def run_search_vulns(message):
    try:
        # Очищаем ввод от опасных символов
        safe_query = re.sub(r'[;&|<>$`]', '', scan_target)
        if not safe_query:
            raise ValueError("Пустой запрос после очистки")
        
        bot.send_message(message.chat.id, f"🔍 Ищу уязвимости для: {safe_query}")
         
        # Формируем команду
        cmd = ["python3", SEARCH_VULNS_SCRIPT, "-q", safe_query]
        
        # Выполняем скрипт
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120  # 2 минуты на выполнение
        )
        
        if result.returncode != 0:
            raise Exception(f"Ошибка скрипта: {result.stderr}")
        
        output = result.stdout.strip()
        
        if not output:
            bot.send_message(message.chat.id, "ℹ️ Уязвимостей не найдено")
            return
            
        # Если найдены CVE - отправляем на анализ ИИ
        if "CVE-" in output:
            ai_report = ask_ai(
                f"Переведи на русский и структурируй информацию об уязвимостях:\n{output}"
            )
            splitted_text = util.smart_split(ai_report, chars_per_string=3000)
            for text in splitted_text:
                bot.send_message(message.chat.id, text)
        else:
            bot.send_message(message.chat.id, f"ℹ️ Результат:\n{output}")
            
    except Exception as e:
        error_msg = f"Ошибка поиска уязвимостей: {str(e)}"
        bot.send_message(message.chat.id, error_msg)
    finally:
        menu_state[message.chat.id] = 'main'
        bot.send_message(message.chat.id, "Выберите следующий инструмент:", reply_markup=create_main_menu())
        
def run_vulners_scan(message):
    try:
        # Генерируем уникальное имя файла
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = re.sub(r'[^a-zA-Z0-9]', '_', scan_target)[:50]
        user_info = f"{message.from_user.id}_{message.from_user.username or 'unknown'}"
        report_filename = f"vulners_{safe_target}_{user_info}_{timestamp}.txt"
        report_path = os.path.join(SCAN_RESULTS_DIR, report_filename)

        bot.send_message(message.chat.id, "🔍 Запускаю сканирование уязвимостей. Это может занять несколько минут...")
        
        # Первое сканирование - поиск открытых портов
        nmap_cmd = ["nmap", "-sS", "--open", "-Pn", scan_target]
        result = subprocess.run(nmap_cmd, capture_output=True, text=True, timeout=NMAP_TIMEOUT)
        
        if result.returncode != 0:
            raise Exception(f"Nmap error: {result.stderr}")
        
        open_ports = parse_open_ports(result.stdout)
        if not open_ports:
            bot.send_message(message.chat.id, "🔒 Открытых портов не обнаружено")
            menu_state[message.chat.id] = 'main'
            bot.send_message(message.chat.id, "Выберите следующий инструмент:", reply_markup=create_main_menu())
            return
        
        bot.send_message(message.chat.id, f"📌 Найдены открытые порты: {', '.join(open_ports)}")
        bot.send_message(message.chat.id, "🔬 Провожу углублённый анализ уязвимостей...")
        
        # Второе сканирование - анализ уязвимостей
        nmap_cmd = [
            "nmap", "-sS", "-p", ",".join(open_ports),
            "-sV", "--script", "vulners", scan_target
        ]
        
        result = subprocess.run(nmap_cmd, capture_output=True, text=True, timeout=ADVANCED_SCAN_TIMEOUT)
        
        if result.returncode != 0:
            raise Exception(f"Nmap error: {result.stderr}")
        
        # Сохраняем полный отчет
        with open(report_path, "w") as f:
            f.write(result.stdout)
        
        # Анализируем уязвимости
        cves = find_cves(result.stdout)
        if not cves:
            bot.send_message(message.chat.id, "✅ Уязвимости не обнаружены")
        else:
            risk_report = generate_risk_report(cves)
            splitted_text = util.smart_split(risk_report, chars_per_string=3000)
            for text in splitted_text:
                bot.send_message(message.chat.id, text)
        
    except subprocess.TimeoutExpired:
        error_msg = "Сканирование превысило лимит времени"
        bot.send_message(message.chat.id, f"⚠️ {error_msg}")
        print_log(message, f"Vulners scan timeout: {error_msg}")
    except Exception as e:
        error_msg = f"Ошибка сканирования: {str(e)}"
        bot.send_message(message.chat.id, f"⚠️ {error_msg}")
        print_log(message, f"Vulners scan failed: {error_msg}")
    finally:
        menu_state[message.chat.id] = 'main'
        bot.send_message(message.chat.id, "Выберите следующий инструмент:", reply_markup=create_main_menu())

def parse_open_ports(nmap_output: str) -> list:
    """Извлекает список открытых портов из вывода nmap"""
    return list(set(re.findall(r'(\d+)/tcp\s+open', nmap_output)))

def find_cves(nmap_output: str) -> list:
    """Ищет CVE уязвимости в выводе nmap"""
    return list(set(re.findall(r'CVE-\d{4}-\d{1,}', nmap_output)))

def get_epss_score(cve: str) -> dict:
    """Получает оценку EPSS для уязвимости через API"""
    try:
        response = requests.get(f"{EPSS_API_URL}?cve={cve}", timeout=10)
        if response.status_code == 200:
            data = response.json()['data'][0]
            return {
                'epss': float(data['epss']),
                'percentile': float(data['percentile'])
            }
    except Exception as e:
        print(f"EPSS request failed for {cve}: {str(e)}")
    return {'epss': 0.0, 'percentile': 0.0}

def get_cvss_data(cve: str) -> dict:
    """Получает данные CVSS для уязвимости через NVD API"""
    try:
        response = requests.get(f"{NVD_API_URL}?cveId={cve}", timeout=10)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            if vulnerabilities:
                metrics = vulnerabilities[0]['cve'].get('metrics', {})
                if 'cvssMetricV31' in metrics:
                    cvss_metric = metrics['cvssMetricV31'][0]
                    return {
                        'version': '3.1',
                        'baseScore': cvss_metric['cvssData']['baseScore'],
                        'vector': cvss_metric['cvssData']['vectorString']
                    }
                elif 'cvssMetricV30' in metrics:
                    cvss_metric = metrics['cvssMetricV30'][0]
                    return {
                        'version': '3.0',
                        'baseScore': cvss_metric['cvssData']['baseScore'],
                        'vector': cvss_metric['cvssData']['vectorString']
                    }
    except Exception as e:
        print(f"NVD API request failed for {cve}: {str(e)}")
    return {'version': 'N/A', 'baseScore': 'N/A', 'vector': 'N/A'}

def generate_risk_report(cves: list) -> str:
    """Генерирует текстовый отчет об оценке рисков"""
    report = ["*Результаты анализа уязвимостей:*\n"]
    total_multiplier = 1.0  # Множитель для расчета общего риска
    vulnerabilities_data = []
    
    for cve in cves:
        epss_data = get_epss_score(cve)
        cvss_data = get_cvss_data(cve)
        
        vuln_info = (
            f"• `{cve}`:\n"
            f"  - CVSS {cvss_data['version']}: {cvss_data['baseScore']} ({cvss_data['vector']})\n"
            f"  - EPSS: {epss_data['epss']:.4f}\n"
            f"  - Percentile: {epss_data['percentile']:.2f}"
        )
        vulnerabilities_data.append(vuln_info)
        
        if epss_data['epss'] > EPSS_SIGNIFICANT_THRESHOLD:
            risk_reduction = 1 - epss_data['epss']
            total_multiplier *= risk_reduction
    
    report.append("\n".join(vulnerabilities_data))
    
    if total_multiplier == 1.0:
        report.append("\n*Нет значимых уязвимостей для расчёта риска*")
    else:
        final_risk = 1 - total_multiplier
        report.append(
            f"\n*ОБЩИЙ РИСК ВЗЛОМА:* {final_risk:.2%}\n"
            f"_Примечание: риск >50% требует немедленного внимания_"
        )
    
    return "\n".join(report)

def run_zap_scan(message):
    try:
        # Генерируем уникальное имя файла
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_url = re.sub(r'[^a-zA-Z0-9]', '_', scan_target)[:50]
        user_info = f"{message.from_user.id}_{message.from_user.username or 'unknown'}_{message.from_user.first_name or ''}_{message.from_user.last_name or ''}"
        report_filename = f"zap_{safe_url}_{user_info}_{timestamp}.json"
        report_path = os.path.join(SCAN_RESULTS_DIR, report_filename)

        bot.send_message(message.chat.id, "Запускаю сканирование ZAP. Это может занять несколько минут...")
        
        # Запускаем ZAP с JSON-отчетом
        zap_command = [
            "java", "-jar", ZAP_PATH,
            "-cmd",
            "-quickurl", scan_target,
            "-quickout", report_path
        ]
        
        process = subprocess.Popen(zap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(timeout=ZAP_TIMEOUT)
        
        if process.returncode != 0:
            raise subprocess.CalledProcessError(process.returncode, zap_command, stderr)
        
        # Читаем JSON отчет
        with open(report_path, "r") as report_file:
            zap_report = json.load(report_file)
        
        # Отправляем уведомление о завершении
        bot.send_message(message.chat.id, f"Сканирование завершено. Технический отчет сохранен. Ждите аналитический AI-отчет.")
        
        # Генерируем AI анализ
        ai_report = ask_ai(json.dumps(zap_report, indent=2))
        
        # Отправляем AI отчет частями
        splitted_text = util.smart_split(ai_report, chars_per_string=3000)
        for text in splitted_text:
            bot.send_message(message.chat.id, text)
        
        # Логируем действие
        print_log(message, f"ZAP scan completed. Report: {report_filename}")
        
    except subprocess.CalledProcessError as e:
        error_msg = f"Ошибка при выполнении ZAP сканирования: {e.stderr}"
        bot.send_message(message.chat.id, error_msg)
        print_log(message, f"ZAP scan failed: {error_msg}")
    except json.JSONDecodeError as e:
        error_msg = "Ошибка при обработке JSON отчета ZAP"
        bot.send_message(message.chat.id, error_msg)
        print_log(message, f"JSON decode error: {str(e)}")
    except Exception as e:
        error_msg = f"Неожиданная ошибка: {str(e)}"
        bot.send_message(message.chat.id, error_msg)
        print_log(message, f"Unexpected error: {str(e)}")
    finally:
        menu_state[message.chat.id] = 'main'
        bot.send_message(message.chat.id, "Выберите следующий инструмент:", reply_markup=create_main_menu())

def run_nuclei_scan(message):
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_url = re.sub(r'[^a-zA-Z0-9]', '_', scan_target)[:50]
        user_info = f"{message.from_user.id}_{message.from_user.username or 'unknown'}"
        report_filename = f"nuclei_{safe_url}_{user_info}_{timestamp}.json"
        report_path = os.path.join(SCAN_RESULTS_DIR, report_filename)

        bot.send_message(message.chat.id, "🔍 Запускаю Nuclei сканирование. Это может занять несколько минут...")
        
        nuclei_cmd = [
            "nuclei",
            "-target", scan_target,
            "-t", "http/cves",
            "-t", "ssl",
            "-nc", 
            "-json-export", report_path,
            "-p", SOCKS5_PROXY
        ]
        
        process = subprocess.Popen(nuclei_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(timeout=NUCLEI_TIMEOUT) 
        
        if process.returncode != 0:
            raise subprocess.CalledProcessError(process.returncode, nuclei_cmd, stderr)
        
        # Читаем JSON отчет
        with open(report_path, "r") as report_file:
            nuclei_report = report_file.read()
        
        # Отправляем уведомление
        bot.send_message(message.chat.id, f"✅ Nuclei сканирование завершено. Анализирую результаты...")
        
        # Генерируем AI отчет
        ai_report = ask_ai(f"Nuclei scan report:\n{nuclei_report[:15000]}")
        
        # Отправляем частями
        for text in util.smart_split(ai_report, chars_per_string=3000):
            bot.send_message(message.chat.id, text)
            
    except subprocess.TimeoutExpired:
        error_msg = "Nuclei сканирование превысило лимит времени (1 час)"
        bot.send_message(message.chat.id, f"⚠️ {error_msg}")
    except Exception as e:
        error_msg = f"Ошибка Nuclei сканирования: {str(e)}"
        bot.send_message(message.chat.id, f"⚠️ {error_msg}")
    finally:
        menu_state[message.chat.id] = 'main'
        bot.send_message(message.chat.id, "Выберите следующий инструмент:", reply_markup=create_main_menu())

def ask_ai(report_text):
    """Генерация AI-отчета по результатам сканирования"""
    try:
        prompt = f"""
Проанализируй этот отчет сканирования и предоставь структурированный отчет на русском языке.
Выдели:
1. Основные уязвимости с оценкой критичности (High/Medium/Low)
2. Рекомендации по исправлению для каждой уязвимости
3. Общую оценку безопасности

Отчет должен быть понятным для технических специалистов.
Вот данные для анализа:
{report_text[:15000]}  # Ограничиваем размер для API
"""
        response = ai_client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {"role": "system", "content": "Ты эксперт по кибербезопасности, который анализирует отчеты сканеров уязвимостей."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=3000
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"⚠️ Ошибка при генерации AI-отчета: {str(e)}\n\nПолный отчет доступен в файле"

def check_target_url(target):
    result = re.match(r'https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)', target)
    return bool(result)

def check_target_ip_or_domain(target):
    lookup = subprocess.run(["host", target], stdout=subprocess.PIPE, text=True).stdout
    addr = target.strip()
    return check_ip(addr) or str(lookup).find('not found') == -1

def check_ip(addr):
    try:
        socket.inet_pton(socket.AF_INET, addr)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, addr)
            return True
        except socket.error:
            return False

def print_help(message):
    help_text = """
<b>Главное меню:</b>
<code>Recon 🕵️</code> - инструменты разведки (nslookup, whois, subfinder)
<code>Scan 🔍</code> - сканирование сетей (IPv4, IPv6, Vulners)
<code>Web 🌐</code> - веб-инструменты (wafcheck, whatweb, ZAP, nuclei)
<code>Others 📚</code> - другие инструменты (creds, search_vulns)

<b>Инструкция:</b>
1. Выберите категорию инструмента
2. Выберите конкретный инструмент
3. Введите цель для проверки
4. Получите результат
"""
    bot.send_message(message.chat.id, help_text, parse_mode='HTML', reply_markup=create_main_menu())

def print_log(message, scan_output):
    with open('log.txt', 'a') as flog:
        flog.write(str(datetime.now()).split('.')[0] + '\n\n')
        flog.write('User ID:    ' + str(message.from_user.id) + '\n')
        flog.write('Username:   ' + str(message.from_user.username) + '\n')
        flog.write('First Name: ' + str(message.from_user.first_name) + '\n')
        flog.write('Last Name:  ' + str(message.from_user.last_name) + '\n')
        flog.write('Is Bot:     ' + str(message.from_user.is_bot) + '\n')
        flog.write('Language:   ' + str(message.from_user.language_code) + '\n')
        flog.write('Target:     ' + scan_target + '\n\n')
        flog.write(scan_output + '\n----------------------------------------------------------------------------------------------------\n\n')

try:
    bot.infinity_polling(timeout=10, long_polling_timeout=5)
except (ConnectionError, telebot.apihelper.ApiException) as e:
    sys.stdout.flush()
    os.execv(sys.argv[0], sys.argv)
else:
    bot.infinity_polling(timeout=10, long_polling_timeout=5)