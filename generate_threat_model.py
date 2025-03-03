import json
from pytm import TM, Server, Datastore, Dataflow, Boundary, Process, Actor, Threat


with open('semgrep_report.json') as f:
    semgrep_data = json.load(f)


tm = TM("Auto-Generated Threat Model")
tm.description = "Modelo criado automaticamente a partir do Semgrep."


internet = Boundary("Internet")

user = Actor("User")
app_server = Server("Flask App")
db = Datastore("Database")

df1 = Dataflow(user, app_server, "User input")
df2 = Dataflow(app_server, db, "DB Query")
df3 = Dataflow(db, app_server, "DB Response")

for result in semgrep_data.get("results", []):
    issue_text = result.get("extra", {}).get("message", "")
    filename = result.get("path", "")
    line_number = result.get("start", {}).get("line", "")

    if "SQL Injection" in issue_text:
        sqli_threat = Threat()
        sqli_threat.description = f"SQL Injection detectado em {filename}, linha {line_number}"
        sqli_threat.rationale = "Entrada não sanitizada pode permitir execução arbitrária de comandos SQL."
        sqli_threat.mitigation = "Utilize queries parametrizadas (ex: cursor.execute('SELECT * FROM users WHERE username = ?', (username,)))"
        sqli_threat.target = db
        tm.threats.append(sqli_threat)

    if "XSS" in issue_text or "Cross-Site Scripting" in issue_text:
        xss_threat = Threat()
        xss_threat.description = f"XSS detectado em {filename}, linha {line_number}"
        xss_threat.rationale = "Entrada do usuário refletida sem sanitização pode permitir injeção de scripts maliciosos."
        xss_threat.mitigation = "Utilize a função `escape()` do Flask ou outra abordagem para sanitização."
        xss_threat.target = app_server
        tm.threats.append(xss_threat)

tm.process()
