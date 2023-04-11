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
    server_score = db.Column(db.String)
    receiver_score = db.Column(db.String)
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
        self.server_score = "0"
        self.receiver_score = "0"


# User Schema
class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'username', 'password', 'email')


# Match Schema
class MatchSchema(ma.Schema):
    class Meta:
        fields = ('match_id', 'set_num', 'game_num', 'server_score', 'receiver_score', 'server', 'receiver',
                  'first_serve_outcome', 'second_serve_outcome', 'winner')


# verified / unverified
# login API
# header for every request will include header "basic auth". Verify before you run code.



# Init Single Schemas
user_schema = UserSchema()
match_schema = MatchSchema()

# Init Multiple Schemas
users_schema = UserSchema(many=True)
matches_schema = MatchSchema(many=True)


# When first starting the db:
with app.app_context():
    db.drop_all()
    db.create_all()


@app.route('/')
def homepage():
    return "Home"


# Add new match
@app.route('/match', methods=['POST'])
def add_match():
    player_one = request.json['player1']  # id
    player_two = request.json['player2']  # id
    starter = request.json['starter']

    new_match = Match(player_one, player_two, starter)

    db.session.add(new_match)
    db.session.commit()

    return match_schema.jsonify(new_match)


# Update match (add in a point)
@app.route('/match/<int:id>', methods=['PUT'])
def add_point(id):
    match = Match.query.get(id)

    set_num = request.json['set']
    game_num = request.json['game']
    server_score = request.json['server_score']
    receiver_score = request.json['receiver_score']
    server = request.json['server']
    receiver = request.json['receiver']
    first_serve_outcome = request.json['first_serve_outcome']
    second_serve_outcome = request.json['second_serve_outcome']
    winner = request.json['winner']

    match.set_num = set_num
    match.game_num = game_num
    match.server_score = server_score
    match.receiver_score = receiver_score
    match.server = server
    match.receiver = receiver
    match.first_serve_outcome = first_serve_outcome
    match.second_serve_outcome = second_serve_outcome
    match.winner = winner

    db.session.commit()  # No need to add before you commit, since its a PUT

    return winner
'''

# Update match 2 (add in a point and calculate details)
@app.route('/match/<int:id>', methods=['PUT'])
def add_point_2(id):
    match = Match.query.get(id)

    first_serve_outcome = request.json['first_serve_outcome']
    second_serve_outcome = request.json['second_serve_outcome']
    winner = request.json['winner']

    match.first_serve_outcome = first_serve_outcome
    match.second_serve_outcome = second_serve_outcome
    match.winner = winner

    # Evaluate match context
    match.set_num = set_num
    match.game_num = game_num
    match.server_score = server_score
    match.receiver_score = receiver_score
    match.server = server
    match.receiver = receiver

    db.session.commit()  # No need to add before you commit, since its a PUT

    return winner
'''


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


@app.route('/match/<int:id1>/<int:id2>', methods=['GET'])
def get_matches(id1, id2):
    matches = Match.query.filter(
        or_(
            and_(Match.server == id1, Match.receiver == id2),
            and_(Match.server == id2, Match.receiver == id1)
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


if __name__ == '__main__':
    app.run(debug=True)
