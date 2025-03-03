import json
from pytm import TM, Server, Datastore, Dataflow, Boundary, Process, Actor, Threat


with open('semgrep_report.json') as f:
    semgrep_data = json.load(f)

tm = TM("Auto-Generated Threat Model")
tm.description = "Modelo criado automaticamente com base no código-fonte."

internet = Boundary("Internet")

user = Actor("User")
app_server = Server("Flask App")
db = Datastore("SQLite Database")

df1 = Dataflow(user, app_server, "User input")
df2 = Dataflow(app_server, db, "DB Query")
df3 = Dataflow(db, app_server, "DB Response")


for result in semgrep_data.get("results", []):
    issue_text = result.get("message", "")
    filename = result.get("path", "")
    line_number = result.get("start", {}).get("line", "")

    if "SQL Injection" in issue_text:
        sqli_threat = Threat(
            "SQL Injection",
            f"SQL Injection detectado em {filename}, linha {line_number}",
            "Entrada não sanitizada pode permitir execução arbitrária de comandos SQL.",
            "Utilize queries parametrizadas (ex: cursor.execute('SELECT * FROM users WHERE username = ?', (username,)))"
        )
        sqli_threat.target = db

    if "XSS" in issue_text:
        xss_threat = Threat(
            "Cross-Site Scripting (XSS)",
            f"XSS detectado em {filename}, linha {line_number}",
            "Entrada do usuário refletida sem sanitização pode permitir injeção de scripts maliciosos.",
            "Utilize a função `escape()` do Flask ou outra abordagem para sanitização."
        )
        xss_threat.target = app_server

tm.process()
