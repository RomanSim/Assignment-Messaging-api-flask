from flask import Flask, request, jsonify, json, make_response
from flask_pymongo import PyMongo
from bson import Binary, Code
from bson.json_util import dumps
from werkzeug.security import generate_password_hash, check_password_hash
import os
import uuid
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config["MONGO_URI"] = os.environ.get("MONGODB_URI", "mongodb://localhost:27017/chat")
mongo = PyMongo(app)
app.config['SECRET_KEY'] = 'secretword'

"""
verify token correctness
user authorization
"""

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            print(data)
            for user in mongo.db.users.find():
                if user["name"] == data["name"]:
                      current_user = user
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/message', methods=['POST'])
def sendMessage():
    mongo.db.messages.insert(request.json)
    return jsonify({'message': 'Message created'})

@app.route('/messages', methods=['GET'])
@token_required
def getMessage(current_user):
    if not current_user:
        return jsonify({'message': 'Not authorized'})
    messages = []
    for message in mongo.db.messages.find():
        if current_user["name"] == message["receiver"]:
            del message["_id"]
            updateMessage = {"$set": {"is_read": True}}
            mongo.db.messages.update(message, updateMessage)
            messages.append(message)
    return jsonify(messages)

@app.route('/messages/unread', methods=['GET'])
@token_required
def unreadMessages(current_user):
    if not current_user:
        return jsonify({'message': 'Not authorized'})
    messages = []
    for message in mongo.db.messages.find():
        if message["receiver"] == current_user["name"] and not message["is_read"]:
            del message["_id"]
            messages.append(message)
    return jsonify(messages)


@app.route('/messages/one', methods=['GET'])
@token_required
def getOneMessage(current_user):
    if not current_user:
        return jsonify({'message': 'Not authorized'})
    message = mongo.db.messages.find_one({"receiver": current_user["name"]})
    del message["_id"]
    updateMessage = {"$set": {"is_read": True}}
    mongo.db.messages.update_one(message, updateMessage)
    return jsonify(message)

@app.route('/messages/delete_one_receiver',methods=['DELETE'])
@token_required
def deleteMessage(current_user):
    if not current_user:
        return jsonify({'message': 'Not authorized'})
    message = mongo.db.messages.find_one_and_delete({"receiver": current_user["name"]})
    del message["_id"]
    return jsonify(message)

@app.route('/messages/delete_one_sender',methods=['DELETE'])
@token_required
def deleteMessageSender(current_user):
    if not current_user:
        return jsonify({'message': 'Not authorized'})
    message = mongo.db.messages.find_one_and_delete({"sender": current_user["name"]})
    del message["_id"]
    return jsonify(message)

@app.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    dict = {"name": data['name'], "password": hashed_password, "public_id": str(uuid.uuid4())}
    mongo.db.users.insert(dict)
    return jsonify({'message': 'New user created'})


"""login, using pyjwt for web token + authentication"""

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required"'})

    for curr_user in mongo.db.users.find():
        if curr_user["name"] == auth.username:
            del curr_user["_id"]
            user = curr_user

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required"'})

    if check_password_hash(user["password"], auth.password):

        token = jwt.encode({'name': user["name"], 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes = 30)}, app.config['SECRET_KEY'])

        return jsonify({'token': token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required"'})


if __name__ == '__main__':# -*- coding: utf-8 -*-
    app.run(debug=True)
