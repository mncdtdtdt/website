import os
import random
import string
import secrets
from PIL import Image
from flask import Flask, request, jsonify, render_template, Blueprint, session
from flask_session import Session
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from time import time
from flask_cors import CORS
from collections import OrderedDict
import binascii
import Crypto
from os import path
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from uuid import uuid4
import json
import hashlib
import requests
from urllib.parse import urlparse

from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.sql import func


auth = Blueprint('auth', __name__)



MINING_SENDER = "The Blockchain"
MINING_REWARD = 1
MINING_DIFFICULTY = 2

db = SQLAlchemy()
DB_NAME = "database.db"


app = Flask(__name__)
app.config['SECRET_KEY'] = 'hjshjhdjah kjshkjdhjs'
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)
CORS(app)
db.init_app(app)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String(10000))
    date = db.Column(db.DateTime(timezone=True), default=func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    


class User(db.Model, UserMixin):
            
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    first_name = db.Column(db.String(150))
    notes = db.relationship('Note')
    private_key = db.Column(db.String(500))
    public_key = db.Column(db.String(500))
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    
    def __repr__(self):
        return f"User('{self.first_name}', '{self.email}', '{self.image_file}')"
    
    
    
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key(format='PEM')
    public_key = key.publickey().export_key(format='PEM')
    return private_key, public_key   
    

  
with app.app_context():

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


class Blockchain:

    def __init__(self):
        self.transactions = []
        self.chain = []
        self.nodes = set()
        self.node_id = str(uuid4()).replace('-', '')
        # Create the genesis block
        self.create_block(0, '00')


    def create_block(self, nonce, previous_hash):
        """
        Add a block of transactions to the blockchain
        """
        block = {'block_number': len(self.chain) + 1,
                 'timestamp': time(),
                 'transactions': self.transactions,
                 'nonce': nonce,
                 'previous_hash': previous_hash}

        # Reset the current list of transactions
        self.transactions = []
        self.chain.append(block)
        return block

    def verify_transaction_signature(self, sender_public_key, signature, transaction):
        public_key = RSA.importKey(binascii.unhexlify(sender_public_key))
        verifier = PKCS1_v1_5.new(public_key)
        h = SHA.new(str(transaction).encode('utf8'))
        try:
            verifier.verify(h, binascii.unhexlify(signature))
            return True
        except ValueError:
            return False

    @staticmethod
    def valid_proof(transactions, last_hash, nonce, difficulty=MINING_DIFFICULTY):
        guess = (str(transactions) + str(last_hash) + str(nonce)).encode('utf8')
        h = hashlib.new('sha256')
        h.update(guess)
        guess_hash = h.hexdigest()
        return guess_hash[:difficulty] == '0' * difficulty

    def proof_of_work(self):
        last_block = self.chain[-1]
        last_hash = self.hash(last_block)
        nonce = 0
        while self.valid_proof(self.transactions, last_hash, nonce) is False:
            nonce += 1

        return nonce

    @staticmethod
    def hash(block):
        # We must to ensure that the Dictionary is ordered, otherwise we'll get inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode('utf8')
        h = hashlib.new('sha256')
        h.update(block_string)
        return h.hexdigest()

    def resolve_conflicts(self):
        neighbours = self.nodes
        new_chain = None

        max_length = len(self.chain)
        for node in neighbours:
            response = requests.get('')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        if new_chain:
            self.chain = new_chain
            return True

        return False

    def valid_chain(self, chain):
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            if block['previous_hash'] != self.hash(last_block):
                return False

            transactions = block['transactions'][:-1]
            transaction_elements = ['sender_public_key', 'recipient_public_key', 'amount']
            transactions = [OrderedDict((k, transaction[k]) for k in transaction_elements) for transaction in
                            transactions]

            if not self.valid_proof(transactions, block['previous_hash'], block['nonce'], MINING_DIFFICULTY):
                return False

            last_block = block
            current_index += 1

        return True

    def submit_transaction(self, sender_public_key, recipient_public_key, signature, amount):
        transaction = OrderedDict({
            'sender_public_key': sender_public_key,
            'recipient_public_key': recipient_public_key,
            'amount': amount
        })

        # Reward for mining a block
        if sender_public_key == MINING_SENDER:
            self.transactions.append(transaction)
            return len(self.chain) + 1
        else:
            # Transaction from wallet to another wallet
            signature_verification = self.verify_transaction_signature(sender_public_key, signature, transaction)
            if signature_verification:
                self.transactions.append(transaction)
                return len(self.chain) + 1
            else:
                return False


class Transaction:

    def __init__(self, sender_public_key, sender_private_key, recipient_public_key, amount):
        self.sender_public_key = sender_public_key
        self.sender_private_key = sender_private_key
        self.recipient_public_key = recipient_public_key
        self.amount = amount

    def to_dict(self):
        return OrderedDict({
            'sender_public_key': self.sender_public_key,
            'recipient_public_key': self.recipient_public_key,
            'amount': self.amount,
        })

    def sign_transaction(self, user):
        private_key = RSA.importKey(binascii.unhexlify(user.private_key.encode('utf-8')))
        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(str(self.to_dict()).encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')


class UpdateAccountForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    public_key = StringField('Public Key',
                        validators=[DataRequired()])
    private_key = StringField('Private Key',
                        validators=[DataRequired()])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != current_user.first_name:
            user = User.query.filter_by(first_name=username.data).first()
            if user:
                raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is taken. Please choose a different one.')



# Instantiate the Blockchain
blockchain = Blockchain()


# Define routes

# Define routes
@app.route('/server')
@login_required
def server():
        
    return render_template('./index.html')




@app.route('/signup', methods=['GET', 'POST'])
def register():
     if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error1')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error1')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error1')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error1')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error1')
            return redirect(url_for('register'))        
        else:
            # Generate private and public keys
            key = RSA.generate(2048)
            private_key = key.export_key(format='DER')
            public_key = key.publickey().export_key(format='DER')
              
             # Create a new user account
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(password1, method='sha256'),
                        private_key=binascii.hexlify(private_key).decode('ascii'),
                        public_key=binascii.hexlify(public_key).decode('ascii'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            
        return redirect(url_for('client_index'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
      if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('client_index'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')
            
    return render_template('login.html', user=current_user)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn



@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.first_name = form.username.data
        current_user.email = form.email.data
        current_user.public_key = form.public_key.data
        current_user.private_key = form.private_key.data
        db.session.commit()
        flash('your account has been updated!', 'succes')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.first_name
        form.email.data = current_user.email
        form.public_key.data = current_user.public_key
        form.private_key.data = current_user.private_key
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('account.html', title='Account', image_file=image_file, form=form )



@app.route('/', methods=['GET', 'POST'])
@login_required
def client_index():
    user = current_user
    public_key = user.public_key
    private_key = user.private_key

    return render_template("client_index.html", user=user, public_key=public_key, private_key=private_key)


@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    sender_public_key = current_user.public_key
    sender_private_key = current_user.private_key
    recipient_public_key = request.form['recipient_public_key']
    amount = request.form['amount']

    transaction = Transaction(sender_public_key, sender_private_key, recipient_public_key, amount)

    response = {
        'transaction': transaction.to_dict(),
        'signature': transaction.sign_transaction(current_user)
    }

    return jsonify(response), 200

@app.route('/wallet/new')
def new_wallet():
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key = private_key.publickey()

    response = {
        'private_key': binascii.hexlify(private_key.export_key(format('DER'))).decode('ascii'),
        'public_key': binascii.hexlify(public_key.export_key(format('DER'))).decode('ascii')
    }

    return jsonify(response), 200



@app.route('/make/transaction')
@login_required
def make_transaction():
    return render_template('make_transaction.html')


@app.route('/view/transactions')
@login_required
def view_transactions():
    return render_template('view_transactions.html')

@app.route('/transactions/get', methods=['GET'])
@login_required
def get_transactions():
    transactions = blockchain.transactions
    response = {'transactions': transactions}
    return jsonify(response), 200


@app.route('/chain', methods=['GET'])
@login_required
def get_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }

    return jsonify(response), 200


@app.route('/mine', methods=['GET'])
def mine():
    # We run the proof of work algorithm
    nonce = blockchain.proof_of_work()

    blockchain.submit_transaction(sender_public_key=MINING_SENDER,
                                  recipient_public_key=blockchain.node_id,
                                  signature='',
                                  amount=MINING_REWARD)

    last_block = blockchain.chain[-1]
    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_block(nonce, previous_hash)

    response = {
        'message': 'New block created',
        'block_number': block['block_number'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }
    return jsonify(response), 200

@app.route('/transactions/new', methods=['POST'])

def new_transaction():
    values = request.form
    required = ['confirmation_sender_public_key', 'confirmation_recipient_public_key', 'transaction_signature',
                'confirmation_amount']
    if not all(k in values for k in required):
        return 'Missing values', 400

    transaction_results = blockchain.submit_transaction(values['confirmation_sender_public_key'],
                                                        values['confirmation_recipient_public_key'],
                                                        values['transaction_signature'],
                                                        values['confirmation_amount'])
    if transaction_results == False:
        response = {'message': 'Invalid transaction/signature'}
        return jsonify(response), 406
    else:
        response = {'message': 'Transaction will be added to the Block ' + str(transaction_results)}
        return jsonify(response), 201



if __name__ == '__main__':

    app.run(host='0.0.0.0', port=5002)
    db.create_all()
    print('Created Database!')
        
