from flask import Flask, jsonify, request, make_response
from flask_socketio import SocketIO
import hashlib
import json
from time import time
from uuid import uuid4
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from cryptography.fernet import Fernet
import jwt
from functools import wraps
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
socketio = SocketIO(app)

node_identifier = str(uuid4()).replace('-', '')

class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.new_block(previous_hash='1', proof=100)

    def new_block(self, proof, previous_hash=None):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }
        self.current_transactions = []
        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, amount, signature):
        transaction = {
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        }
        if self.verify_transaction(sender, transaction, signature):
            self.current_transactions.append(transaction)
            return self.last_block['index'] + 1
        else:
            return None

    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self):
        return self.chain[-1]

    def proof_of_work(self, last_proof):
        proof = 0
        while not self.valid_proof(last_proof, proof):
            proof += 1
        return proof

    @staticmethod
    def valid_proof(last_proof, proof):
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

    @staticmethod
    def sign_transaction(private_key_hex, transaction):
        sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
        transaction_string = json.dumps(transaction, sort_keys=True).encode()
        signature = sk.sign(transaction_string)
        return signature.hex()

    @staticmethod
    def verify_transaction(public_key_hex, transaction, signature_hex):
        try:
            vk = VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=SECP256k1)
            transaction_string = json.dumps(transaction, sort_keys=True).encode()
            signature = bytes.fromhex(signature_hex)
            return vk.verify(signature, transaction_string)
        except Exception as e:
            print(f"Verification failed: {e}")
            return False

    def get_balance(self, address):
        balance = 0
        for block in self.chain:
            for transaction in block['transactions']:
                if transaction['recipient'] == address:
                    balance += transaction['amount']
                if transaction['sender'] == address:
                    balance -= transaction['amount']
        return balance

blockchain = Blockchain()

# Загрузка ключа шифрования
with open("encryption_key.key", "rb") as key_file:
    encryption_key = key_file.read()

cipher = Fernet(encryption_key)

# Секретный ключ для JWT
SECRET_KEY = app.config['SECRET_KEY']

# Декоратор для проверки токена и роли
def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = request.headers.get('x-access-tokens')
            if not token:
                return jsonify({'message': 'Token is missing!'}), 403
            try:
                data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
                user_role = data.get('role', 'guest')
                if user_role != required_role:
                    return jsonify({'message': 'Permission denied!'}), 403
            except jwt.ExpiredSignatureError:
                return jsonify({'message': 'Token has expired!'}), 403
            except jwt.InvalidTokenError:
                return jsonify({'message': 'Token is invalid!'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

@app.route('/login', methods=['POST'])
def login():
    auth = request.authorization
    if auth and auth.password == 'password':  # Проверьте правильность проверки
        token = jwt.encode({'user': auth.username, 'role': 'admin'}, SECRET_KEY, algorithm="HS256")
        return jsonify({'token': token})
    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

@app.route('/')
def index():
    return jsonify(message="Welcome to the SOM Blockchain API")

@app.route('/mine', methods=['GET'])
@role_required('admin')
def mine():
    last_block = blockchain.last_block
    last_proof = last_block['proof']
    proof = blockchain.proof_of_work(last_proof)

    blockchain.new_transaction(
        sender="0",
        recipient=node_identifier,
        amount=1,
        signature=""
    )

    block = blockchain.new_block(proof)
    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200

@app.route('/transactions/new', methods=['POST'])
@role_required('user')
def new_transaction():
    values = request.get_json()
    required = ['sender', 'recipient', 'amount', 'signature']
    if not all(k in values for k in required):
        return 'Missing values', 400

    index = blockchain.new_transaction(values['sender'], values['recipient'], values['amount'], values['signature'])
    if index is not None:
        response = {'message': f'Transaction will be added to Block {index}'}
        return jsonify(response), 201
    else:
        response = {'message': 'Invalid transaction'}
        return jsonify(response), 400

@app.route('/chain', methods=['GET'])
@role_required('guest')
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

@app.route('/balance/<address>', methods=['GET'])
@role_required('user')
def get_balance(address):
    balance = blockchain.get_balance(address)
    response = {'balance': balance}
    return jsonify(response), 200

@app.route('/secure-data', methods=['GET'])
@role_required('admin')
def secure_data():
    return jsonify({'message': 'This is secured data!'})

@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('new_transaction')
def handle_new_transaction(data):
    socketio.emit('update', data)

@socketio.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)
