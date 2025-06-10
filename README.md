
# ScanParadis v2.5 - Telegram Bot for Security Scanning

## 📌 Описание

ScanParadis - это многофункциональный Telegram бот для проведения легальных проверок безопасности. Бот предоставляет набор инструментов для разведки, сканирования сетей, анализа веб-приложений и проверки уязвимостей.

## 🌟 Основные возможности

- **Recon**: Инструменты разведки (nslookup, whois, subfinder)
- **Scan**: Сканирование сетей (IPv4, IPv6, Vulners)
- **Web**: Анализ веб-приложений (wafcheck (через tor), whatweb, ZAP, nuclei (через tor))
- **Others**: Дополнительные инструменты (creds)

## 🔥 Новое в v2.5
- Добавлен **поиск уязвимостей ПО** в разделе Others
- Интеграция с ИИ для перевода и структурирования результатов
- Безопасная обработка пользовательского ввода

## 🔧 Установка и настройка

### Требования
- Python 3.8+
- Установленные зависимости: `pip install -r requirements.txt`
- Доступ к API OpenAI (для AI-анализа)
- Java (для работы ZAP)
- Nmap с установленным скриптом vulners (`apt install nmap`)
- Nuclei v3.4+ (`go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`)
- subfinder v2.7+ (`go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`)
- ZAP v2.16+ (`https://www.zaproxy.org/download/`)
- search_vulns (`https://github.com/ra1nb0rn/search_vulns`)

### Установка
1. Клонируйте репозиторий:
   ```bash
   git clone https://github.com/yourusername/scanparadis.git
   cd scanparadis
   ```

2. Установите зависимости:
   ```bash
   pip install -r requirements.txt
   ```

3. Настройте конфигурацию в файле `config.json`:
   ```json
   {
      "TELEGRAM_BOT_TOKEN": "YOUR_TELEGRAM_BOT_TOKEN",
      "ZAP_PATH": "/opt/ZAP_2.16.1/zap-2.16.1.jar",
      "OPENAI_API_KEY": "YOUR_OPENAI_API_KEY",
      "OPENAI_BASE_URL": "https://api.proxyapi.ru/deepseek",
      "OPENAI_MODEL": "deepseek-chat",
      "SCAN_RESULTS_DIR": "scanresults",
      "EPSS_API_URL": "https://api.first.org/data/v1/epss",
      "NVD_API_URL": "https://services.nvd.nist.gov/rest/json/cves/2.0",
      "EPSS_SIGNIFICANT_THRESHOLD": 0.1,
      "NMAP_TIMEOUT": 600,
      "ZAP_TIMEOUT": 1800,
      "NUCLEI_TIMEOUT": 1800,
      "ADVANCED_SCAN_TIMEOUT": 1200,
      "SOCKS5_PROXY": "socks5://127.0.0.1:9050",
      "HTTP_PROXY": "http://127.0.0.1:8118",
      "SEARCH_VULNS_SCRIPT": "/opt/search_vulns/search_vulns.py"
   }
   ```

4. Создайте директорию для результатов сканирования:
   ```bash
   mkdir scanresults
   ```

## 🚀 Запуск бота
```bash
python3 bot.py
```

## 🛠 Команды и использование

Основные команды доступны через меню:
- `/start`, `/help` - Начало работы и справка
- Главное меню:
  - Recon 🕵️ - Инструменты разведки
  - Scan 🔍 - Сканирование сетей
  - Web 🌐 - Веб-инструменты
  - Others 📚 - Другие инструменты

## 📊 Примеры использования

1. **Сканирование уязвимостей (Vulners)**:
   - Выберите "Scan 🔍" → "Vulners"
   - Введите IP-адрес или доменное имя
   - Получите отчет с оценкой рисков

2. **Анализ веб-приложения (ZAP, nuclei)**:
   - Выберите "Web 🌐" → "ZAP" или "Nuclei"
   - Введите URL сайта
   - Получите технический отчет и AI-анализ

3. **Проверка учетных данных (creds)**:
   - Выберите "Others 📚" → "creds"
   - Введите название вендора или ПО
   - Получите информацию о стандартных учетных данных
4. **Пример использования поиска уязвимостей**:
   - Выберите `Others` → `search_vulns`
   - Введите название ПО и версию:
       - `Apache 2.4.55`
       - `WordPress 6.4.2`
   - Получите:
       - Список CVE уязвимостей
       - AI-анализ на русском языке
       - Рекомендации по обновлению


## 📁 Структура проекта
```
scanparadis/
├── bot.py             # Основной код бота
├── config.json        # Файл конфигурации
├── requirements.txt   # Зависимости
├── scanresults/       # Директория для результатов сканирования
└── README.md          # Этот файл
```

## ⚠️ Важное предупреждение
- Используйте бот только для легальных проверок
- Получайте разрешение перед сканированием любых систем
- Бот предназначен для образовательных и профессиональных целей

## 🤝 Участие в разработке
Приветствуются пул-реквесты и сообщения о проблемах. Перед внесением изменений:
1. Форкните репозиторий
2. Создайте ветку с вашими изменениями
3. Отправьте пул-реквест

## 📜 Лицензия
MIT License. 

---

Разработано с ❤️ для сообщества специалистов по безопасности
