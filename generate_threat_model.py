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


sids_existentes = set()


for idx, resultado in enumerate(semgrep_data.get("results", []), start=1):
    mensagem = resultado.get("extra", {}).get("message", "")
    arquivo = resultado.get("path", "")
    linha = resultado.get("start", {}).get("line", "")

   
    sid = f"THREAT-{idx:04d}"

    if sid in sids_existentes:
        continue  

    sids_existentes.add(sid)  

    try:
        ameaca = Threat(SID=sid)
        ameaca.description = f"Ameaça detectada em {arquivo}, linha {linha}: {mensagem}"
        ameaca.rationale = "Descrição detalhada da ameaça."
        ameaca.mitigation = "Medidas de mitigação recomendadas."
        ameaca.target = servidor_app if "XSS" in mensagem else banco_dados
        tm.threats.append(ameaca)
    except ValueError as e:
        logging.error(f"Erro ao criar ameaça: {e}")


try:
    tm.process()
    logging.info("Modelo de ameaças gerado com sucesso.")
except Exception as e:
    logging.error(f"Erro ao processar o modelo de ameaças: {e}")
    exit(1)
