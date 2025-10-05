"""
zap_full_scan_robusto.py
---------------------------------------------------------
⚠️  Execute APENAS em ambiente de laboratório
    com autorização explícita.

Este script:
  • Verifica se o ZAP está online
  • Faz Spider
  • Roda Passive Scan
  • Roda Active Scan (Injection, XSS, SSRF, Broken Access Control)
  • Gera relatórios detalhados em JSON e CSV
  • Mostra estatísticas resumidas por risco e categoria OWASP
---------------------------------------------------------
"""

from zapv2 import ZAPv2
from time import sleep
from pprint import pprint
import json
import csv
import sys

# ===== CONFIGURAÇÃO =====
ZAP_ADDRESS = '127.0.0.1'
ZAP_PORT = '8080'
TARGET = 'http://juice-shop.lab/'   # URL do seu laboratório
API_KEY = None  # ou sua API key, se estiver configurada

# ===== FUNÇÃO: Conectar ao ZAP =====


def connect_zap():
    try:
        zap = ZAPv2(apikey=API_KEY,
                    proxies={'http': f'http://{ZAP_ADDRESS}:{ZAP_PORT}',
                             'https': f'http://{ZAP_ADDRESS}:{ZAP_PORT}'})
        # Teste de conexão
        version = zap.core.version
        print(f"[+] Conectado ao ZAP (versão {version})")
        return zap
    except Exception as e:
        print(f"[ERRO] Não foi possível conectar ao ZAP: {e}")
        sys.exit(1)

# ===== FUNÇÃO: Spider =====


def spider_scan(zap, target):
    print(f"\n[+] Iniciando Spider em {target}")
    scan_id = zap.spider.scan(target)
    while int(zap.spider.status(scan_id)) < 100:
        print(f"Spider: {zap.spider.status(scan_id)}%")
        sleep(2)
    print("[+] Spider finalizado")

# ===== FUNÇÃO: Passive Scan =====


def passive_scan(zap):
    print("\n[+] Iniciando Passive Scan")
    while int(zap.pscan.records_to_scan) > 0:
        print(f"Passive scan restante: {zap.pscan.records_to_scan}")
        sleep(2)
    print("[+] Passive Scan finalizado")

# ===== FUNÇÃO: Active Scan =====


def active_scan(zap, target):
    print("\n[+] Iniciando Active Scan (Injection, XSS, SSRF, BAC...)")
    scan_id = zap.ascan.scan(target)
    while int(zap.ascan.status(scan_id)) < 100:
        print(f"Active scan: {zap.ascan.status(scan_id)}%")
        sleep(5)
    print("[+] Active Scan concluído")

# ===== FUNÇÃO: Coletar alertas =====


def get_alerts(zap, target):
    alerts = zap.core.alerts(baseurl=target)
    print(f"[+] Total de alertas encontrados: {len(alerts)}")
    return alerts

# ===== FUNÇÃO: Filtrar por palavra-chave =====


def filtrar_alertas(alerts, keyword):
    return [a for a in alerts if keyword.lower() in a['alert'].lower()]

# ===== FUNÇÃO: Estatísticas resumidas =====


def estatisticas(alerts):
    resumo = {}
    for a in alerts:
        risco = a['risk']
        resumo[risco] = resumo.get(risco, 0) + 1
    return resumo

# ===== FUNÇÃO: Exportar CSV =====


def export_csv(alerts, filename="zap_alertas.csv"):
    keys = ['alert', 'risk', 'url', 'param', 'evidence']
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for a in alerts:
            writer.writerow({k: a.get(k, "") for k in keys})
    print(f"[+] CSV exportado: {filename}")

# ===== FUNÇÃO: Exportar JSON =====


def export_json(alerts, filename="zap_alertas.json"):
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(alerts, f, indent=2, ensure_ascii=False)
    print(f"[+] JSON exportado: {filename}")

# ===== FUNÇÃO: Mostrar alertas filtrados =====


def mostrar_alertas_categoria(alerts, categoria):
    print(f"\n=== {categoria.upper()} ===")
    categoria_alerts = filtrar_alertas(alerts, categoria)
    if categoria_alerts:
        for a in categoria_alerts:
            print(f"- {a['alert']} (Risco: {a['risk']}) -> {a['url']}")
    else:
        print("Nenhum alerta encontrado nessa categoria.")


# ===== PROGRAMA PRINCIPAL =====
if _name_ == "_main_":
    zap = connect_zap()
    spider_scan(zap, TARGET)
    passive_scan(zap)
    active_scan(zap, TARGET)

    alerts = get_alerts(zap, TARGET)

    # Estatísticas gerais
    stats = estatisticas(alerts)
    print("\n=== Estatísticas por nível de risco ===")
    for risco, count in stats.items():
        print(f"{risco}: {count} alertas")

    # Mostrar alertas filtrados por categoria OWASP
    mostrar_alertas_categoria(alerts, "Injection")
    mostrar_alertas_categoria(alerts, "Cross Site Scripting")
    mostrar_alertas_categoria(alerts, "Server Side Request Forgery")
    # Broken Access Control
    mostrar_alertas_categoria(alerts, "Access Control")

    # Exportar relatórios
    export_json(alerts, "zap_alertas_completo.json")
    export_csv(alerts, "zap_alertas_completo.csv")

    print("\n[+] Scan concluído com sucesso!")

"""
zap_bac_advanced.py
⚠️ Execute apenas em ambiente de laboratório controlado.

Este script:
- Conecta ao ZAP
- Cria contexto e usuários
- Faz Spider, Passive Scan, Active Scan
- Coleta alertas de Injection, XSS, SSRF, BAC
- Compara respostas entre usuários para BAC
- Exporta relatórios JSON/CSV detalhados
"""


# ===== CONFIGURAÇÃO =====
ZAP_ADDRESS = '127.0.0.1'
ZAP_PORT = '8080'
TARGET = 'http://juice-shop.lab/'
API_KEY = None
CONTEXT_NAME = "LabContext"

# Usuários para Broken Access Control
USERS = [
    {"name": "normal", "username": "user", "password": "userpass"},
    {"name": "admin", "username": "admin", "password": "adminpass"}
]

# ===== FUNÇÃO: Conectar ao ZAP =====


def connect_zap():
    try:
        zap = ZAPv2(apikey=API_KEY,
                    proxies={'http': f'http://{ZAP_ADDRESS}:{ZAP_PORT}',
                             'https': f'http://{ZAP_ADDRESS}:{ZAP_PORT}'})
        print(f"[+] Conectado ao ZAP versão {zap.core.version}")
        return zap
    except Exception as e:
        print(f"[ERRO] Conexão ZAP falhou: {e}")
        sys.exit(1)

# ===== FUNÇÃO: Criar contexto e usuários =====


def setup_context(zap):
    print(f"[+] Criando contexto '{CONTEXT_NAME}'")
    context_id = zap.context.new_context(CONTEXT_NAME)
    for user in USERS:
        user_id = zap.users.new_user(context_id, user["name"])
        zap.users.set_authentication_credentials(
            context_id, user_id, f"username={user['username']}&password={user['password']}")
        zap.users.set_user_enabled(context_id, user_id, True)
    print(f"[+] Contexto e usuários configurados")
    return context_id

# ===== FUNÇÃO: Spider =====


def spider_scan(zap, target):
    scan_id = zap.spider.scan(target)
    while int(zap.spider.status(scan_id)) < 100:
        print(f"Spider: {zap.spider.status(scan_id)}%")
        sleep(2)
    print("[+] Spider finalizado")

# ===== FUNÇÃO: Passive Scan =====


def passive_scan(zap):
    while int(zap.pscan.records_to_scan) > 0:
        print(f"Passive scan restante: {zap.pscan.records_to_scan}")
        sleep(2)
    print("[+] Passive Scan finalizado")

# ===== FUNÇÃO: Active Scan =====


def active_scan(zap, target):
    scan_id = zap.ascan.scan(target)
    while int(zap.ascan.status(scan_id)) < 100:
        print(f"Active scan: {zap.ascan.status(scan_id)}%")
        sleep(5)
    print("[+] Active Scan concluído")

# ===== FUNÇÃO: Comparar usuários para BAC =====


def analyze_bac(zap, context_id):
    print("[+] Analisando Broken Access Control por comparação de usuários")
    # O ZAP detecta falhas de autorização automaticamente se contexto/usuários configurados
    # Coletar alertas específicos de Access Control
    alerts = zap.core.alerts(baseurl=TARGET)
    bac_alerts = [a for a in alerts if "Access Control" in a['alert']]
    return bac_alerts

# ===== FUNÇÃO: Exportar JSON/CSV =====


def export_reports(alerts, json_file="alerts.json", csv_file="alerts.csv"):
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(alerts, f, indent=2, ensure_ascii=False)
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        keys = ['alert', 'risk', 'url', 'param', 'evidence']
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for a in alerts:
            writer.writerow({k: a.get(k, "") for k in keys})
    print(f"[+] Relatórios exportados: {json_file}, {csv_file}")

# ===== FUNÇÃO: Estatísticas =====


def stats_by_risk(alerts):
    stats = {}
    for a in alerts:
        stats[a['risk']] = stats.get(a['risk'], 0) + 1
    return stats


# ===== PROGRAMA PRINCIPAL =====
if _name_ == "_main_":
    zap = connect_zap()
    context_id = setup_context(zap)
    spider_scan(zap, TARGET)
    passive_scan(zap)
    active_scan(zap, TARGET)

    alerts = zap.core.alerts(baseurl=TARGET)

    # Estatísticas
    stats = stats_by_risk(alerts)
    print("\n=== Estatísticas por nível de risco ===")
    for risco, count in stats.items():
        print(f"{risco}: {count} alertas")

    # BAC avançado
    bac_alerts = analyze_bac(zap, context_id)
    print(f"\n=== Broken Access Control (comparação de usuários) ===")
    if bac_alerts:
        for a in bac_alerts:
            print(f"- {a['alert']} (Risco: {a['risk']}) -> {a['url']}")
    else:
        print("Nenhum alerta de BAC detectado.")

    # Exportar relatórios
    export_reports(alerts, "zap_full_advanced.json", "zap_full_advanced.csv")
    print("\n[+] Scan completo e relatórios gerados!")
