import json
from pytm import TM, Server, Datastore, Dataflow, Boundary, Actor, Threat


mapeamento_ameacas = {
    "SQL Injection": "INP05",
    "XSS": "INP39",
    "Cross-Site Scripting": "INP40",
    "Privilege Escalation": "AC12",
    "Command Injection": "INP31",
    "Code Injection": "INP26",
    "Session Hijacking": "AC17",
    "CSRF": "AC21",
    "LDAP Injection": "INP09",
    "XML Injection": "INP32",
    "Remote Code Execution": "INP33",
    "File Inclusion": "INP16",
    "Authentication Bypass": "AA01",
    "API Manipulation": "LB01",
    "Buffer Overflow": "INP07"
}


tm = TM("Modelo de Ameaças")
tm.description = "Modelo gerado a partir dos resultados do Semgrep."


usuario = Actor("usuario")
servidor = Server("servidor")
banco_dados = Datastore("banco_dados")


Dataflow(usuario, servidor, "Requisição HTTP")
Dataflow(servidor, banco_dados, "Consulta SQL")
Dataflow(banco_dados, servidor, "Resposta SQL")
Dataflow(servidor, usuario, "Resposta HTTP")


with open('semgrep_report.json') as f:
    semgrep_data = json.load(f)


for idx, resultado in enumerate(semgrep_data.get("results", []), start=1):
    mensagem = resultado.get("extra", {}).get("message", "")
    arquivo = resultado.get("path", "")
    linha = resultado.get("start", {}).get("line", "")

    
    threat_code = next((code for key, code in mapeamento_ameacas.items() if key.lower() in mensagem.lower()), "INP14")

    
    alvo = "servidor" if "XSS" in mensagem else "banco_dados"

    
    Threat(
        SID=threat_code,
        description=f"Ameaça detectada em {arquivo}, linha {linha}: {mensagem}",
        target=alvo  
    )


tm.process()
