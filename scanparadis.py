#!/usr/bin/python3

#
# ScanParadis v1.10
#

import telebot
import subprocess
import re
from datetime import datetime
import json
import socket
import os, sys
from telebot import util


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

bot =  telebot.TeleBot(TELEGRAM_BOT_TOKEN)

scan_target = ''

@bot.message_handler(content_types=['text'])

########################################################################################################################
### Get text messages ##################################################################################################
########################################################################################################################

def get_text_messages(message):

  if message.text == "/start":
    bot.send_message(message.from_user.id, "Бот предназначен исключительно для легальных проверок")
    print_help(message)
  elif message.text == "/help":
    print_help(message)
  elif message.text == "/IPv4scan":
    bot.send_message(message.from_user.id, "Необходимо задать параметры сканирования")
    bot.send_message(message.from_user.id, "Укажите один IPv4 адрес или одно доменное имя")
    bot.send_message(message.from_user.id, "в формате 1.1.1.1 или www.example.com")
    bot.register_next_step_handler(message, get_target_and_run, "nmap4");
  elif message.text == "/IPv6scan":
    bot.send_message(message.from_user.id, "Необходимо задать один IPv6 адрес или одно доменное имя для сканирования")
    bot.send_message(message.from_user.id, "в формате 2a00:1450:4026:804::2004 или www.example.com")
    bot.register_next_step_handler(message, get_target_and_run, "nmap6");
  elif message.text == "/wafcheck":
    bot.send_message(message.from_user.id, "Необходимо задать url для сканирования")
    bot.send_message(message.from_user.id, "в формате https://www.example.com")
    bot.register_next_step_handler(message, get_target_and_run , "wafw00f");
  elif message.text == "/whatweb":
    bot.send_message(message.from_user.id, "Необходимо задать url для сканирования")
    bot.send_message(message.from_user.id, "в формате https://www.example.com")
    bot.register_next_step_handler(message, get_target_and_run, "whatweb");
  elif message.text == "/nslookup":
    bot.send_message(message.from_user.id, "Необходимо задать одно доменное имя")
    bot.send_message(message.from_user.id, "в формате host.example.com")
    bot.register_next_step_handler(message, get_target_and_run, "nslookup");
  elif message.text == "/whois":
    bot.send_message(message.from_user.id, "Необходимо задать один ip-адрес")
    bot.send_message(message.from_user.id, "в формате 1.1.1.1 или 2a00:1450:4026:804::2004")
    bot.register_next_step_handler(message, get_target_and_run, "whois");
  elif message.text == "/creds":
    bot.send_message(message.from_user.id, "Необходимо задать наименование вендора или ПО")
    bot.register_next_step_handler(message, get_target_and_run, "creds");
  else:
    bot.send_message(message.from_user.id, "Команда не распознана. Попробуйте /help.")


########################################################################################################################
def get_target_and_run(message, proc="nslookup"):
  global scan_target
# remove RCE tail and mask  
  scan_target = message.text.strip().split(";")[0].split("|")[0].split("&")[0]

  if ( check_target_ip_or_domain(scan_target) or check_target_url(scan_target) or proc == "creds"):
    run_utils(message, proc)
  else:
    bot.send_message(message.from_user.id, "Указан некорректный адрес. Попробуйте еще раз.")
    print_help(message)

########################################################################################################################
def run_utils(message, proc):

  bot.send_message(message.from_user.id, "Придется немного подождать...")
  i = 0

  if proc == "nmap4":
    scan_result = subprocess.Popen(["/usr/bin/nmap", "-sS", "-F", scan_target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    scan_output, scan_error = scan_result.communicate()
    scan_result.wait()
    i = scan_output.find('Nmap scan')
  elif proc == "nmap6":
    scan_result = subprocess.Popen(["/usr/bin/nmap", "-sS", "-F", "-6", scan_target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    scan_output, scan_error = scan_result.communicate()
    scan_result.wait()
    i = scan_output.find('Nmap scan')
  elif proc == "wafw00f":
    scan_result = subprocess.Popen(["wafw00f", "-a", scan_target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    scan_output, scan_error = scan_result.communicate()
    scan_result.wait()
    i = scan_output.find('Checking')
  elif proc == "whatweb":
    scan_result = subprocess.Popen(["whatweb", "--color=never", scan_target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    scan_output, scan_error = scan_result.communicate()
    scan_result.wait()
  elif proc == "nslookup":
    scan_result = subprocess.Popen(["host", scan_target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    scan_output, scan_error = scan_result.communicate()
    scan_result.wait()
  elif proc == "whois":
    scan_result = subprocess.Popen(["whois", scan_target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    scan_output, scan_error = scan_result.communicate()
    scan_result.wait()
  elif proc == "creds":
    scan_result = subprocess.Popen(["/opt/DefaultCreds-cheat-sheet/creds", "search", scan_target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    scan_output, scan_error = scan_result.communicate()
    scan_result.wait()

  splitted_text = util.smart_split(scan_output[i:], chars_per_string=3000)
  for text in splitted_text:
    bot.send_message(message.from_user.id, text)

  print_log(message, scan_output)
  print_help(message)

########################################################################################################################
def check_target_url(target):

  result = re.match(r'https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)' , target)

  if result:
      return True
  else:
    return False

########################################################################################################################
def check_target_ip_or_domain(target):
  
  lookup = subprocess.run(["host", target], stdout=subprocess.PIPE, text=True).stdout

  addr = target.strip()
  if check_ip(addr):
    return True
  elif str(lookup).find('not found') == -1:
    return True
  else:
    return False

########################################################################################################################
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

########################################################################################################################
def print_help(message):
  bot.send_message(message.from_user.id, "Список команд:")
  bot.send_message(message.from_user.id, "/help     - список команд")
  bot.send_message(message.from_user.id, "/IPv4scan - сканирование портов IPv4")
  bot.send_message(message.from_user.id, "/IPv6scan - сканирование портов IPv6")
  bot.send_message(message.from_user.id, "/wafcheck - проверка наличия WAF")
  bot.send_message(message.from_user.id, "/whatweb  - информация о web-сервере")
  bot.send_message(message.from_user.id, "/nslookup - резолвинг доменных имен")
  bot.send_message(message.from_user.id, "/whois    - определение владельца сети")
  bot.send_message(message.from_user.id, "/creds    - пароли по умолчанию")


########################################################################################################################
def print_log(message, scan_output):

  flog = open('log.txt', 'a')
  
  flog.write(str(datetime.now()).split('.')[0] + '\n\n')
  flog.write('User ID:    ' + str(message.from_user.id) + '\n')
  flog.write('Username:   ' + str(message.from_user.username) + '\n')
  flog.write('First Name: ' + str(message.from_user.first_name) + '\n')
  flog.write('Last Name:  ' + str(message.from_user.last_name) + '\n')
  flog.write('Is Bot:     ' + str(message.from_user.is_bot) + '\n')
  flog.write('Language:   ' + str(message.from_user.language_code) + '\n')
  flog.write('Target:     ' + scan_target + '\n\n')
  flog.write(scan_output + '\n----------------------------------------------------------------------------------------------------\n\n')
  flog.close()


########################################################################################################################
########################################################################################################################
########################################################################################################################
  
try:
    bot.infinity_polling(timeout=10, long_polling_timeout=5)
except (ConnectionError, ReadTimeout) as e:
    sys.stdout.flush()
    os.execv(sys.argv[0], sys.argv)
else:
    bot.infinity_polling(timeout=10, long_polling_timeout=5)

########################################################################################################################
########################################################################################################################
########################################################################################################################


