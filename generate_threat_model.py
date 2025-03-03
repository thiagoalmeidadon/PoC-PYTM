import json
from pytm import TM, Server, Datastore, Dataflow, Boundary, Actor, Threat


with open('semgrep_report.json') as f:
    semgrep_data = json.load(f)


tm = TM("Modelo de Ameaças")
tm.description = "Modelo gerado a partir dos resultados do Semgrep."


usuario = Actor("Usuário")
servidor = Server("Servidor Web")
banco_dados = Datastore("Banco de Dados")


Dataflow(usuario, servidor, "Requisição HTTP")
Dataflow(servidor, banco_dados, "Consulta SQL")
Dataflow(banco_dados, servidor, "Resposta SQL")
Dataflow(servidor, usuario, "Resposta HTTP")


for idx, resultado in enumerate(semgrep_data.get("results", []), start=1):
    mensagem = resultado.get("extra", {}).get("message", "")
    arquivo = resultado.get("path", "")
    linha = resultado.get("start", {}).get("line", "")

    
    alvo = servidor if "XSS" in mensagem else banco_dados

    threat = Threat(
        SID=f"THREAT-{idx:04d}",
        description=f"Ameaça detectada em {arquivo}, linha {linha}: {mensagem}",
        target=(alvo,)  
    )

    tm.add(threat)  


tm.process()
