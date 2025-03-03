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
internal_network = Boundary("Rede Interna")


usuario = Actor("Usuário", inBoundary=internet)
servidor_app = Server("Aplicação Flask", inBoundary=internal_network)
banco_dados = Datastore("Banco de Dados", inBoundary=internal_network)
servico_externo = Server("Serviço Externo", inBoundary=internet)


fluxo1 = Dataflow(usuario, servidor_app, "Entrada do Usuário")
fluxo2 = Dataflow(servidor_app, banco_dados, "Consulta ao BD")
fluxo3 = Dataflow(banco_dados, servidor_app, "Resposta do BD")
fluxo4 = Dataflow(servidor_app, servico_externo, "Chamada API Externa")
fluxo5 = Dataflow(servico_externo, servidor_app, "Resposta API Externa")


existing_sids = set()

existing_threats = set()

for resultado in semgrep_data.get("results", []):
    mensagem = resultado.get("extra", {}).get("message", "")
    arquivo = resultado.get("path", "")
    linha = resultado.get("start", {}).get("line", "")

    threat_key = f"{mensagem}-{arquivo}-{linha}"
    if threat_key in existing_threats:
        continue
    existing_threats.add(threat_key)

    
    sid = f"T{len(existing_sids) + 1}"
    while sid in existing_sids:
        sid = f"T{len(existing_sids) + 1}"
    existing_sids.add(sid)

    try:
        ameaca = Threat(SID=sid)
        ameaca.description = f"{mensagem} detectado em {arquivo}, linha {linha}"
        ameaca.rationale = "Descrição detalhada da ameaça."
        ameaca.mitigation = "Mitigações recomendadas."
        
        
        if "SQL Injection" in mensagem:
            ameaca.target = banco_dados
        elif "Cross-Site Scripting" in mensagem or "XSS" in mensagem:
            ameaca.target = servidor_app
        elif "Mass Assignment" in mensagem:
            ameaca.target = servidor_app
        elif "Improper Validation" in mensagem:
            ameaca.target = servidor_app
        elif "Code Injection" in mensagem:
            ameaca.target = servidor_app
        elif "Active Debug Code" in mensagem:
            ameaca.target = servidor_app
        else:
            ameaca.target = servidor_app  # Alvo padrão se não for especificado

        tm.threats.append(ameaca)

    except ValueError as e:
        logging.error(f"Erro ao criar ameaça: {e}")

try:
    tm.process()
    logging.info("Modelo de ameaças gerado com sucesso.")
except Exception as e:
    logging.error(f"Erro ao processar o modelo de ameaças: {e}")
    exit(1)