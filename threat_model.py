from pytm import TM, Server, Datastore, Dataflow, Boundary

tm = TM("PoC Threat Model")
tm.description = "Modelo de ameaça simples para uma app vulnerável"

internet = Boundary("Internet")

user = Server("User")
app_server = Server("App Server")
db = Datastore("Database")

df1 = Dataflow(user, app_server, "User input")
df2 = Dataflow(app_server, db, "DB Query")
df3 = Dataflow(db, app_server, "DB Response")

tm.process()
