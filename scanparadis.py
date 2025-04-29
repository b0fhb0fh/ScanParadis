#!/usr/bin/python3

#
# ScanParadis v1.20 (with hierarchical menu)
#

import telebot
import subprocess
import re
from datetime import datetime
import json
import socket
import os, sys
from telebot import util
from telebot.types import ReplyKeyboardMarkup, KeyboardButton, ReplyKeyboardRemove


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

bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)

scan_target = ''
menu_state = {}  # Для отслеживания состояния меню пользователей

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
    btn3 = KeyboardButton('Назад ↩️')
    
    markup.add(btn1, btn2, btn3)
    return markup

# Меню Scan
def create_scan_menu():
    markup = ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
    
    btn1 = KeyboardButton('IPv4scan')
    btn2 = KeyboardButton('IPv6scan')
    btn3 = KeyboardButton('Назад ↩️')
    
    markup.add(btn1, btn2, btn3)
    return markup

# Меню Web
def create_web_menu():
    markup = ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
    
    btn1 = KeyboardButton('wafcheck')
    btn2 = KeyboardButton('whatweb')
    btn3 = KeyboardButton('Назад ↩️')
    
    markup.add(btn1, btn2, btn3)
    return markup

# Меню Others
def create_others_menu():
    markup = ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
    
    btn1 = KeyboardButton('creds')
    btn2 = KeyboardButton('Назад ↩️')
    
    markup.add(btn1, btn2)
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
    
    # Обработка подменю Web
    elif menu_state.get(chat_id) == 'web':
        if message.text == 'wafcheck':
            bot.send_message(chat_id, "Укажите url в формате https://www.example.com", 
                            reply_markup=ReplyKeyboardRemove())
            bot.register_next_step_handler(message, get_target_and_run, "wafw00f")
        elif message.text == 'whatweb':
            bot.send_message(chat_id, "Укажите url в формате https://www.example.com", 
                            reply_markup=ReplyKeyboardRemove())
            bot.register_next_step_handler(message, get_target_and_run, "whatweb")
    
    # Обработка подменю Others
    elif menu_state.get(chat_id) == 'others':
        if message.text == 'creds':
            bot.send_message(chat_id, "Укажите наименование вендора или ПО", 
                            reply_markup=ReplyKeyboardRemove())
            bot.register_next_step_handler(message, get_target_and_run, "creds")
    
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

    if (check_target_ip_or_domain(scan_target) or check_target_url(scan_target) or proc == "creds"):
        run_utils(message, proc)
    else:
        bot.send_message(message.chat.id, "Указан некорректный адрес. Попробуйте еще раз.", 
                        reply_markup=create_main_menu())
        print_help(message)

def run_utils(message, proc):
    bot.send_message(message.chat.id, "Придется немного подождать...")
    
    commands = {
        "nmap4": ["/usr/bin/nmap", "-sS", "-F", scan_target],
        "nmap6": ["/usr/bin/nmap", "-sS", "-F", "-6", scan_target],
        "wafw00f": ["wafw00f", "-a", scan_target],
        "whatweb": ["whatweb", "--color=never", scan_target],
        "nslookup": ["host", scan_target],
        "whois": ["whois", scan_target],
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
<code>Recon 🕵️</code> - инструменты разведки (nslookup, whois)
<code>Scan 🔍</code> - сканирование сетей (IPv4, IPv6)
<code>Web 🌐</code> - веб-инструменты (wafcheck, whatweb)
<code>Others 📚</code> - другие инструменты (creds)

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