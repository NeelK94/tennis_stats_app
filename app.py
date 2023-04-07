from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import os

# Init app
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))  # make the base directory same as this file location
# Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Init db
db = SQLAlchemy(app)
# Init ma
ma = Marshmallow(app)


# Product Class/Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(10), unique=True)
    # firstName = db.Column(db.String(30))
    # lastName = db.Column(db.String(30))
    password = db.Column(db.String)
    email = db.Column(db.String)

    def __init__(self, username, password, email):
        self.username = username
        self.password = password
        self.email = email


# User Schema
class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'username', 'password', 'email')


# Init Schema
user_schema = UserSchema()
users_schema = UserSchema(many=True)  # This initiates a schema for multiple users

# When first starting the db:
with app.app_context():
    db.create_all()


@app.route('/')
def homepage():
    return "Home"


@app.route('/user', methods=['POST'])
def add_user():
    username = request.json['username']
    password = request.json['password']
    email = request.json['email']

    new_user = User(username, password, email)

    db.session.add(new_user)
    db.session.commit()

    return user_schema.jsonify(new_user)


# Get all users
@app.route('/user', methods=['GET'])
def get_users():
    all_users = User.query.all()  # This is an sqlquery query! No SQL
    result = users_schema.dump(all_users)
    return jsonify(result)


# Get single users
@app.route('/user/<id>', methods=['GET'])
def get_user(id):
    user = User.query.get(id)
    result = user_schema.jsonify(user)
    return result


# Update user
@app.route('/user/<id>', methods=['PUT'])
def update_user(id):
    user = User.query.get(id)

    username = request.json['username']
    password = request.json['password']
    email = request.json['email']

    user.username = username
    user.password = password
    user.email = email

    new_user = User(username, password, email)

    db.session.commit()  # No need to add before you commit, since its a PUT

    return user_schema.jsonify(new_user)


# delete user
@app.route('/user/<id>', methods=['DELETE'])
def delete_user(id):
    user = User.query.get(id)
    db.session.delete(user)
    db.session.commit()
    result = user_schema.jsonify(user)
    return result



'''
conn = sqlite3.connect("tennis.db")

# define columns to be used when creating players table
user_columns = [
    "id INTEGER PRIMARY KEY",
    "username VARCHAR UNIQUE",
    "password VARCHAR",
    "email VARCHAR"
]

# Create table for players
conn.execute(f"CREATE TABLE players ({','.join(user_columns)})")
cur = conn.cursor()


# Populate users initially
users_db = [
    "11111, 'NeelPeel', 'Iliketennis123', 'neel-k94@hotmail.com'",
    "11112, 'Antipesto', 'password11', 'adil.khokhar@yahoo.com'",
    "11113, 'BunceyTheCat', 'Iamacat!!', 'big.boosh@gmail.com'"
]

for user in users_db:
    conn.execute(f"INSERT INTO players VALUES ({user})")

conn.commit()

cur.execute("SELECT * FROM players")

for person in cur.fetchall():
    print(person)

users = [
    {"id": "aaa111",
     "username": "NeelPeel",
     "password": "Iliketennis123",
     "email": "neel-k94@hotmail.com"
     },
    {"id": "aaa112",
     "username": "Antipesto",
     "password": "password11",
     "email": "adil.khokhar@yahoo.com"
     },
    {"id": "aaa113",
     "username": "BunceyTheCat",
     "password": "Iamacat!!",
     "email": "big.boosh@gmail.com"
     }
]

games = [
    {"gameid": "00001",
     "player1": "aaa111",
     "player2": "aaa112",
     "winner": "aaa111"}
]


def valid_user(username):
    for user in users:
        if user["username"] == username:
            return False
    return True


def verify_login(username, password):
    global users
    for user in users:
        if user["username"] == username:
            if user["password"] == password:
                return True
    return False


@app.route("/")
def home_page():
    return "Welcome to the home page!"


@app.route("/players")
def list_players():
    global users
    return jsonify(users)


@app.route("/user", methods=['POST'])
def add_player():
    global users
    record = request.json
    if valid_user(record["username"]):
        new_user = {"id": str(uuid.uuid4()),
                    "username": record["username"],
                    "password": record["password"],
                    "email": record["email"]}
        users.append(new_user)
        return jsonify(new_user)
    else:
        return "That username is taken!"


@app.route("/login", methods=['POST'])
def login():
    global users
    record = request.json  # Json or username and password
    if verify_login(record["username"], record["password"]):
        return f"Welcome {record['username']}"
    return "Login details incorrect"


@app.route("/user/closeAccount", methods=['POST'])
def delete_account():
    global users
    record = request.json  # Username and password
    new_list = []
    if verify_login(record["username"], record["password"]):
        for user in users:
            if user["username"] == record["username"]:
                users.remove(user)
                return "User deleted"
    return "Invalid credentials!"


@app.route("/user/update/newPassword", methods=['POST'])
def update_password():
    global users
    record = request.json
    for user in users:
        if user["username"] == record["username"]:
            user.update({"password": record["new_password"]})
            return "Password changed"
    return "User not found"


@app.route("/user/update/newEmail", methods=['POST'])
def update_email():
    global users
    record = request.json
    for user in users:
        if user["username"] == record["username"]:
            user["email"] = record["new_email"]
            return "Email address changed"
    return "User not found"
'''

if __name__ == '__main__':
    app.run(debug=True)
