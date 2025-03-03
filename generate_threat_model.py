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


existing_sids = set()


for idx, resultado in enumerate(semgrep_data.get("results", []), start=1):
    mensagem = resultado.get("extra", {}).get("message", "")
    arquivo = resultado.get("path", "")
    linha = resultado.get("start", {}).get("line", "")

    threat_key = f"{mensagem}-{arquivo}-{linha}"  

    if threat_key in existing_sids:
        continue  

    existing_sids.add(threat_key)  

    sid_hash = f"{idx:04d}"  

    try:
        if "SQL Injection" in mensagem:
            ameaca_sqli = Threat(SID=f"SQLI-{sid_hash}")
            ameaca_sqli.description = f"SQL Injection detectado em {arquivo}, linha {linha}"
            ameaca_sqli.rationale = "Entrada não sanitizada pode permitir execução arbitrária de comandos SQL."
            ameaca_sqli.mitigation = "Utilize consultas parametrizadas para evitar injeção de SQL."
            ameaca_sqli.target = banco_dados
            tm.threats.append(ameaca_sqli)

        if "XSS" in mensagem or "Cross-Site Scripting" in mensagem:
            ameaca_xss = Threat(SID=f"XSS-{sid_hash}")
            ameaca_xss.description = f"XSS detectado em {arquivo}, linha {linha}"
            ameaca_xss.rationale = "Entrada do usuário refletida sem sanitização pode permitir injeção de scripts maliciosos."
            ameaca_xss.mitigation = "Sanitize a entrada do usuário antes de renderizar no HTML."
            ameaca_xss.target = servidor_app
            tm.threats.append(ameaca_xss)
    
    except ValueError as e:
        logging.error(f"Erro ao criar ameaça: {e}")


try:
    tm.process()
    logging.info("Modelo de ameaças gerado com sucesso.")
except Exception as e:
    logging.error(f"Erro ao processar o modelo de ameaças: {e}")
    exit(1)
