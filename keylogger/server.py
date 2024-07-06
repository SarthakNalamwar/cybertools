from flask import Flask, request

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload():
    data = request.json.get('data')
    with open('received_data.txt', 'a') as file:
        file.write(data + '\n')
    return 'Data received', 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
