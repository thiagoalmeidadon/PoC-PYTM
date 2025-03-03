from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)  
    user = cursor.fetchone()
    
    if user:
        return "Login bem-sucedido!"
    else:
        return "Falha no login!", 401

@app.route("/greet", methods=["GET"])
def greet():
    name = request.args.get("name", "Guest")
    
    return render_template_string(f"<h1>Olá, {name}!</h1>")

if __name__ == "__main__":
    app.run(debug=True)
