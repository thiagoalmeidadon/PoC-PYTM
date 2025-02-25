from flask import Flask, request

app = Flask(__name__)

@app.route('/vulnerable', methods=['GET'])
def vulnerable():
    user_input = request.args.get('input')
    return f"User input: {user_input}" 

if __name__ == '__main__':
    app.run(debug=True)
