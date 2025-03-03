import json
import logging
from pytm import TM, Server, Datastore, Dataflow, Boundary, Actor, Threat


logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


try:
    with open('semgrep_report.json') as f:
        semgrep_data = json.load(f)
except FileNotFoundError:
    logging.error("Arquivo 'semgrep_report.json' não encontrado. Verifique se o Semgrep foi executado corretamente.")
    exit(1)
except json.JSONDecodeError:
    logging.error("Erro ao decodificar 'semgrep_report.json'. Verifique se o arquivo está corrompido.")
    exit(1)


tm = TM("Auto-Generated Threat Model")
tm.description = "Modelo criado automaticamente a partir do Semgrep."


internet = Boundary("Internet")


usuario = Actor("Usuário")
servidor_app = Server("Aplicação Flask")
banco_dados = Datastore("Banco de Dados")


fluxo1 = Dataflow(usuario, servidor_app, "Entrada do Usuário")
fluxo2 = Dataflow(servidor_app, banco_dados, "Consulta ao BD")
fluxo3 = Dataflow(banco_dados, servidor_app, "Resposta do BD")


contador_ameacas = 1


existing_threats = set()


for resultado in semgrep_data.get("results", []):
    mensagem = resultado.get("extra", {}).get("message", "")
    arquivo = resultado.get("path", "")
    linha = resultado.get("start", {}).get("line", "")

    threat_key = f"{mensagem}-{arquivo}-{linha}"  

    if threat_key in existing_threats:
        continue  

    existing_threats.add(threat_key)  

    if "SQL Injection" in mensagem:
        try:
            ameaca_sqli = Threat(SID=f"SQLI-{contador_ameacas}")
            ameaca_sqli.description = f"SQL Injection detectado em {arquivo}, linha {linha}"
            ameaca_sqli.rationale = "Entrada não sanitizada pode permitir execução arbitrária de comandos SQL."
            ameaca_sqli.mitigation = "Utilize consultas parametrizadas para evitar injeção de SQL."
            ameaca_sqli.target = banco_dados
            tm.threats.append(ameaca_sqli)
            contador_ameacas += 1
        except ValueError as e:
            logging.error(f"Erro ao criar ameaça SQL Injection: {e}")

    if "XSS" in mensagem or "Cross-Site Scripting" in mensagem:
        try:
            ameaca_xss = Threat(SID=f"XSS-{contador_ameacas}")
            ameaca_xss.description = f"XSS detectado em {arquivo}, linha {linha}"
            ameaca_xss.rationale = "Entrada do usuário refletida sem sanitização pode permitir injeção de scripts maliciosos."
            ameaca_xss.mitigation = "Sanitize a entrada do usuário antes de renderizar no HTML."
            ameaca_xss.target = servidor_app
            tm.threats.append(ameaca_xss)
            contador_ameacas += 1
        except ValueError as e:
            logging.error(f"Erro ao criar ameaça XSS: {e}")


try:
    tm.process()
    logging.info("Modelo de ameaças gerado com sucesso.")
except Exception as e:
    logging.error(f"Erro ao processar o modelo de ameaças: {e}")
    exit(1)
