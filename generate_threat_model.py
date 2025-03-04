import json
import pytm
import pytm.pytm

from pytm import TM, Actor, Server, Datastore, Dataflow, Threat
from pytm.pytm import TM as TM_class


vuln_map = {
    "sql injection": "INP05",
    "xss": "INP39"
}


tm = TM("Threat Model gerado pelo Semgrep")
tm.description = "Exemplo para versões antigas do PyTM que requerem monkey patch"


servidor = Server("ServidorWeb")
banco_dados = Datastore("BancoDeDados")
usuario = Actor("Usuario")


pytm.pytm.ServidorWeb = servidor
pytm.pytm.BancoDeDados = banco_dados
pytm.pytm.Usuario = usuario

Dataflow(usuario, servidor, "Request")
Dataflow(servidor, banco_dados, "Query")
Dataflow(banco_dados, servidor, "Response")
Dataflow(servidor, usuario, "Response")


with open("semgrep_report.json", "r", encoding="utf-8") as f:
    semgrep_data = json.load(f)


for idx, result in enumerate(semgrep_data.get("results", []), start=1):
    msg = result.get("extra", {}).get("message", "")
    arquivo = result.get("path", "")
    linha = result.get("start", {}).get("line", "")

    
    lower_msg = msg.lower()
    sid_encontrado = "INP14"  
    for termo, sid_valor in vuln_map.items():
        if termo in lower_msg:
            sid_encontrado = sid_valor
            break

    
    threat = Threat(
        SID=sid_encontrado,
        name=f"Achado Semgrep #{idx}",
        description=f"Ameaça detectada em {arquivo}, linha {linha}: {msg}",
        target="ServidorWeb"
    )

    
    TM_class._threats.append(threat)


tm.process()
