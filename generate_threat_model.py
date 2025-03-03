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


contador_sqli = 1
contador_xss = 1
contador_mass_assignment = 1
contador_improper_validation = 1
contador_code_injection = 1
contador_debug_code = 1

existing_threats = set()

for resultado in semgrep_data.get("results", []):
    mensagem = resultado.get("extra", {}).get("message", "")
    arquivo = resultado.get("path", "")
    linha = resultado.get("start", {}).get("line", "")

    threat_key = f"{mensagem}-{arquivo}-{linha}"
    if threat_key in existing_threats:
        continue
    existing_threats.add(threat_key)

    try:
        if "SQL Injection" in mensagem:
            ameaca_sqli = Threat(SID=f"SQLI-{contador_sqli}")
            ameaca_sqli.description = f"SQL Injection detectado em {arquivo}, linha {linha}"
            ameaca_sqli.rationale = "Entrada não sanitizada pode permitir execução arbitrária de comandos SQL."
            ameaca_sqli.mitigation = "Utilize consultas parametrizadas para evitar injeção de SQL."
            ameaca_sqli.target = banco_dados
            tm.threats.append(ameaca_sqli)
            contador_sqli += 1

        elif "Cross-Site Scripting" in mensagem or "XSS" in mensagem:
            ameaca_xss = Threat(SID=f"XSS-{contador_xss}")
            ameaca_xss.description = f"XSS detectado em {arquivo}, linha {linha}"
            ameaca_xss.rationale = "Entrada do usuário refletida sem sanitização pode permitir injeção de scripts maliciosos."
            ameaca_xss.mitigation = "Sanitize a entrada do usuário antes de renderizar no HTML."
            ameaca_xss.target = servidor_app
            tm.threats.append(ameaca_xss)
            contador_xss += 1

        elif "Mass Assignment" in mensagem:
            ameaca_mass_assignment = Threat(SID=f"MA-{contador_mass_assignment}")
            ameaca_mass_assignment.description = f"Mass Assignment detectado em {arquivo}, linha {linha}"
            ameaca_mass_assignment.rationale = "Uso indevido de atribuição em massa pode levar à modificação não autorizada de atributos."
            ameaca_mass_assignment.mitigation = "Use validações e filtros adequados para controlar quais campos podem ser atualizados."
            ameaca_mass_assignment.target = servidor_app
            tm.threats.append(ameaca_mass_assignment)
            contador_mass_assignment += 1

        elif "Improper Validation" in mensagem:
            ameaca_improper_validation = Threat(SID=f"IV-{contador_improper_validation}")
            ameaca_improper_validation.description = f"Improper Validation detectado em {arquivo}, linha {linha}"
            ameaca_improper_validation.rationale = "Validação inadequada de entrada pode levar a várias vulnerabilidades de segurança."
            ameaca_improper_validation.mitigation = "Implemente validações rigorosas para todas as entradas do usuário."
            ameaca_improper_validation.target = servidor_app
            tm.threats.append(ameaca_improper_validation)
            contador_improper_validation += 1

        elif "Code Injection" in mensagem:
            ameaca_code_injection = Threat(SID=f"CI-{contador_code_injection}")
            ameaca_code_injection.description = f"Code Injection detectado em {arquivo}, linha {linha}"
            ameaca_code_injection.rationale = "Injeção de código pode permitir a execução de código arbitrário no servidor."
            ameaca_code_injection.mitigation = "Evite a criação de templates com formatação de strings. Use métodos seguros de renderização de templates."
            ameaca_code_injection.target = servidor_app
            tm.threats.append(ameaca_code_injection)
            contador_code_injection += 1

        elif "Active Debug Code" in mensagem:
            ameaca_debug_code = Threat(SID=f"ADC-{contador_debug_code}")
            ameaca_debug_code.description = f"Active Debug Code detectado em {arquivo}, linha {linha}"
            ameaca_debug_code.rationale = "O uso de modo de depuração ativo pode expor informações sensíveis."
            ameaca_debug_code.mitigation = "Não habilite o modo de depuração em ambientes de produção. Use variáveis de configuração ou variáveis de ambiente para controlar isso."
            ameaca_debug_code.target = servidor_app
            tm.threats.append(ameaca_debug_code)
            contador_debug_code += 1

    except ValueError as e:
        logging.error(f"Erro ao criar ameaça: {e}")

try:
    tm.process()
    logging.info("Modelo de ameaças gerado com sucesso.")
except Exception as e:
    logging.error(f"Erro ao processar o modelo de ameaças: {e}")
    exit(1)