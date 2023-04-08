from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_, and_
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


# User Class/Model
class User(db.Model):
    __tablename__ = "Users"

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


# Match Class/Model

class Match(db.Model):

    __tablename__ = "Matches"

    match_id = db.Column(db.Integer, primary_key=True)
    set_num = db.Column(db.Integer)
    game_num = db.Column(db.Integer)
    server = db.Column(db.Integer)  # ref user with id
    receiver = db.Column(db.Integer)  # ref user with id
    first_serve_outcome = db.Column(db.String)
    second_serve_outcome = db.Column(db.String)
    winner = db.Column(db.Integer)  # ref user with id

    def __init__(self, player_one, player_two, starter):
        self.player_one = player_one
        self.player_two = player_two
        if starter == 2:
            self.server = player_one
            self.receiver = player_two
        else:
            self.server = player_two
            self.receiver = player_one
        self.set_num = 1
        self.game_num = 1



# User Schema
class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'username', 'password', 'email')


# Match Schema
class MatchSchema(ma.Schema):
    class Meta:
        fields = ('match_id', 'set_num', 'game_num', 'server', 'receiver', 'first_serve_outcome', 'second_serve_outcome'
                  , 'winner')


# Init Single Schemas
user_schema = UserSchema()
match_schema = MatchSchema()

# Init Multiple Schemas
users_schema = UserSchema(many=True)
matches_schema = MatchSchema(many=True)

# When first starting the db:
with app.app_context():
    db.create_all()


@app.route('/')
def homepage():
    return "Home"


@app.route('/match', methods=['POST'])
def add_match():
    player_one = request.json['player1']
    player_two = request.json['player2']
    starter = request.json['starter']

    new_match = Match(player_one, player_two, starter)

    db.session.add(new_match)
    db.session.commit()

    return match_schema.jsonify(new_match)

@app.route('/match', methods=['GET'])
def list_matches():
    matches = Match.query.all()
    result = matches_schema.dump(matches)
    return jsonify(result)

@app.route('/match/<int:id>', methods=['GET'])
def get_match(id):
    match = Match.query.get(id)
    result = user_schema.jsonify(match)
    return result


@app.route('/match/<string:name1>/<string:name2>', methods=['GET'])
def get_matches(name1, name2):
    matches = Match.query.filter(
        or_(
            and_(Match.server == name1, Match.receiver == name2),
            and_(Match.server == name2, Match.receiver == name1)
        )
    ).all()

    return matches_schema.jsonify(matches)

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


# Get single users by name
@app.route('/user/<string:name>', methods=['GET'])
def get_user_by_name(name):
    user = User.query.filter(User.username == name).all()[0]
    result = user_schema.jsonify(user)
    return result


# Get single users
@app.route('/user/<int:id>', methods=['GET'])
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
