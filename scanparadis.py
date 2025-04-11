#!/usr/bin/python3

# ScanParadis v1.9
#
# creds
#

import telebot
import subprocess
import re
from datetime import datetime
import requests
import json
import socket
import os, sys
from requests.exceptions import ConnectionError, ReadTimeout
from telebot import util


bot_api_key = 'MY_BOT_API_KEY'
bot =  telebot.TeleBot(bot_api_key)

my_user_id = 59369872

scan_target = ''
scan_params = ''

@bot.message_handler(content_types=['text'])

########################################################################################################################
### Get text messages ##################################################################################################
########################################################################################################################

def get_text_messages(message):

  if message.text == "/start":
    bot.send_message(message.from_user.id, "Бот предназначен для сканирования целей в Интернете (кроме зон RU и BY)")
    bot.send_message(message.from_user.id, "Сканирование зоны RU и BY не ведется")
    print_help(message)

  elif message.text == "/help":
    print_help(message)

  elif message.text == "/IPv4scan":
    bot.send_message(message.from_user.id, "Необходимо задать параметры сканирования")
    bot.send_message(message.from_user.id, "Укажите один IPv4 адрес или одно доменное имя")
    bot.send_message(message.from_user.id, "в формате 1.1.1.1 или www.example.com")
    bot.register_next_step_handler(message, get_target_addr_and_scan, "4");

  elif message.text == "/netscan":
    bot.send_message(message.from_user.id, "Необходимо задать параметры сканирования")
    bot.send_message(message.from_user.id, "Укажите один IPv4 адрес сети и порт сканирования")
    bot.send_message(message.from_user.id, "в формате '1.1.1.1/24 80'. Маска сети >=24")
    bot.register_next_step_handler(message, get_target_net_addr_and_scan);

  elif message.text == "/IPv6scan":
    bot.send_message(message.from_user.id, "Необходимо задать один IPv6 адрес или одно доменное имя для сканирования")
    bot.send_message(message.from_user.id, "в формате 2a00:1450:4026:804::2004 или www.example.com")
    bot.register_next_step_handler(message, get_target_addr_and_scan, "6");

  elif message.text == "/wafcheck":
    bot.send_message(message.from_user.id, "Необходимо задать url для сканирования")
    bot.send_message(message.from_user.id, "в формате https://www.example.com")
    bot.register_next_step_handler(message, get_target_url_and_run , "wafw00f");

  elif message.text == "/whatweb":
    bot.send_message(message.from_user.id, "Необходимо задать url для сканирования")
    bot.send_message(message.from_user.id, "в формате https://www.example.com")
    bot.register_next_step_handler(message, get_target_url_and_run, "whatweb");

  elif message.text == "/nslookup":
    bot.send_message(message.from_user.id, "Необходимо задать одно доменное имя")
    bot.send_message(message.from_user.id, "в формате host.example.com")
    bot.register_next_step_handler(message, get_target_addr_and_run_utils, "nslookup");

  elif message.text == "/whois":
    bot.send_message(message.from_user.id, "Необходимо задать один ip-адрес")
    bot.send_message(message.from_user.id, "в формате 1.1.1.1 или 2a00:1450:4026:804::2004")
    bot.register_next_step_handler(message, get_target_addr_and_run_utils, "whois");

  elif message.text == "/creds":
    bot.send_message(message.from_user.id, "Необходимо задать наименование вендора или ПО")
    bot.register_next_step_handler(message, get_creds);

  else:
    bot.send_message(message.from_user.id, "Команда не распознана. Попробуйте /help.")


########################################################################################################################
### /IPv4scan /IPv6scan /netscan #######################################################################################
########################################################################################################################

def get_target_addr_and_scan(message, ipv="4"):
  global scan_target
  scan_target = message.text

  if check_target_ip_or_domain(scan_target, ipv):
    start_port_scan(message, ipv)

  else:
    bot.send_message(message.from_user.id, "Указан некорректный адрес. Попробуйте еще раз.")
    print_help(message)

########################################################################################################################

def get_target_net_addr_and_scan(message):
  global scan_target
  scan_target = message.text

  ip = message.text.strip().split("/")[0]
  mask = int(message.text.strip().split("/")[1].split(" ")[0])
  port = int(message.text.strip().split(" ")[1])

  if mask >= 24 and mask <= 32 and port > 0 and port <= 65535 and port != 25 and check_target_ip_or_domain(ip):
    scan_target = ip + "/" + str(mask)
    start_net_scan(message, port)

  else:
    bot.send_message(message.from_user.id, "Указан некорректный адрес. Попробуйте еще раз.")
    print_help(message)

########################################################################################################################

def start_port_scan(message, ipv="4"):
  if ipv == "4":
    scan_result = subprocess.Popen(["/usr/bin/nmap", "-sS", "-F", scan_target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
  else:
    scan_result = subprocess.Popen(["/usr/bin/nmap", "-sS", "-F", "-6",  scan_target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

  scan_output, scan_error = scan_result.communicate()
  scan_result.wait()

  i = scan_output.find('Nmap scan')
  bot.send_message(message.from_user.id, scan_output[i:])

  print_log(message, scan_output)
  print_help(message)

########################################################################################################################

def start_net_scan(message, port):
  scan_result = subprocess.Popen(["nmap", "-sS", scan_target, "-p", str(port)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

  scan_output, scan_error = scan_result.communicate()
  scan_result.wait()
  
  i = scan_output.find('Nmap scan')

  splitted_text = util.smart_split(scan_output[i:], chars_per_string=3000)
  for text in splitted_text:
    bot.send_message(message.from_user.id, text)

  print_log(message, scan_output)
  print_help(message)


########################################################################################################################
### /wafcheck ##########################################################################################################
########################################################################################################################

def run_waf_util(message):
  global scan_target

  bot.send_message(message.from_user.id, "Придется немного подождать...")

  scan_result = subprocess.Popen(["wafw00f", "-a", scan_target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
  scan_output, scan_error = scan_result.communicate()
  scan_result.wait()

  i = scan_output.find('Checking')
  bot.send_message(message.from_user.id, scan_output[i:])

  print_log(message, scan_output)
  print_help(message)

########################################################################################################################
### /creds #############################################################################################################
########################################################################################################################

def get_creds(message):
  target = message.text.strip().split("/")[0].split(";")[0].split("|")[0].split("&")[0]

  scan_result = subprocess.Popen(["/opt/DefaultCreds-cheat-sheet/creds", "search", target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
  scan_output, scan_error = scan_result.communicate()
  scan_result.wait()

  splitted_text = util.smart_split(scan_output, chars_per_string=3000)
  for text in splitted_text:
    bot.send_message(message.from_user.id, text)


  print_log(message, scan_output)
  print_help(message)

########################################################################################################################
### /whatweb ###########################################################################################################
########################################################################################################################

def run_whatweb_util(message):
  global scan_target

  bot.send_message(message.from_user.id, "Придется немного подождать...")

  scan_result = subprocess.Popen(["whatweb", "--color=never", scan_target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
  scan_output, scan_error = scan_result.communicate()
  scan_result.wait()

  bot.send_message(message.from_user.id, scan_output)

  print_log(message, scan_output)
  print_help(message)

########################################################################################################################
### /nslookup and other network utils ##################################################################################
########################################################################################################################

def get_target_addr_and_run_utils(message, proc="nslookup"):
  global scan_target
  scan_target = message.text

  # Для whois проверяем строго IP-адрес, для nslookup - домен или IP
  if (proc == "whois" and check_ip(scan_target)) or (proc == "nslookup" and check_target_ip_or_domain(scan_target, "4")):
    run_utils(message, proc)
  else:
    bot.send_message(message.from_user.id, "Указан некорректный адрес. Попробуйте еще раз.")
    print_help(message)

########################################################################################################################

def run_utils(message, proc):

  if proc == "nslookup":
    scan_result = subprocess.Popen(["host", scan_target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
  elif proc == "whois":
    scan_result = subprocess.Popen(["whois", scan_target], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

  scan_output, scan_error = scan_result.communicate()
  scan_result.wait()

  bot.send_message(message.from_user.id, scan_output)

  print_log(message, scan_output)
  print_help(message)


########################################################################################################################
### Common procedures ##################################################################################################
########################################################################################################################

def get_target_url_and_run(message, proc='wafw00f'):
  global scan_target

  scan_target = message.text.split(';')[0].split('&')[0].split('|')[0] # удаление хвоста с возможными командами ОС

  if check_target_url(message, scan_target):
    if proc == 'wafw00f':
      run_waf_util(message)
    elif proc == 'whatweb':
      run_whatweb_util(message)

    return

  else:
    bot.send_message(message.from_user.id, "Указан некорректный url. Попробуйте еще раз /wafcheck.")

########################################################################################################################

def check_target_url(message, target):
  global my_user_id

  result = re.match(r'https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)' , target)

  if result:
      return True
  else:
    return False

########################################################################################################################

def check_target_ip_or_domain(target, ipv="4"):

  if target.find('/') >= 0 or target.find(';') >= 0 or target.find('&') >= 0 or target.find('|') >= 0:
    return False

  lookup = subprocess.run(["host", target], stdout=subprocess.PIPE, text=True).stdout

  if ipv == "4" or ipv == "6":
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
  bot.send_message(message.from_user.id, "/netscan  - сканирование сети с маской 24-32 по одному порту")
  bot.send_message(message.from_user.id, "/wafcheck - проверка наличия WAF")
  bot.send_message(message.from_user.id, "/whatweb  - информация о web-сервере")
  bot.send_message(message.from_user.id, "/nslookup - резолвинг доменных имен")
  bot.send_message(message.from_user.id, "/whois    - определение владельца сети")
  bot.send_message(message.from_user.id, "/creds    - пароли по умолчанию")
  bot.send_message(message.from_user.id, "Не осуществляется:")
  bot.send_message(message.from_user.id, "  - сканирование по tcp 25")

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

