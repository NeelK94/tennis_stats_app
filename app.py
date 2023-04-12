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
    player_1_id = db.Column(db.Integer)
    player_2_id = db.Column(db.Integer)
    time_stamp = db.Column(db.DateTime)
    winner = db.Column(db.Integer)
    loser = db.Column(db.Integer)
    status = db.Column(db.String)  # Unsent, Sent, Verified, Declined

    def __init__(self, player_1_id, player_2_id, time_stamp, winner, loser):
        self.player_1_id = player_1_id
        self.player_2_id = player_2_id
        self.time_stamp = time_stamp
        self.winner = winner
        self.loser = loser
        self.status = "Unsent"



# Points Class/Model

class Points(db.Model):
    __tablename__ = "Points"

    point_id = db.Column(db.Integer, primary_key=True)
    match_id = db.Column(db.Integer)

    point_num = db.Column(db.Integer)

    server_id = db.Column(db.Integer)
    receiver_id = db.Column(db.Integer)

    server_sets = db.Column(db.Integer)
    receiver_sets = db.Column(db.Integer)
    server_games = db.Column(db.Integer)
    receiver_games = db.Column(db.Integer)
    server_score = db.Column(db.String)
    receiver_score = db.Column(db.String)

    first_serve_outcome = db.Column(db.String)
    second_serve_outcome = db.Column(db.String)

    winner_id = db.Column(db.Integer)


# User Schema
class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'username', 'password', 'email')


# Match Schema
class MatchSchema(ma.Schema):
    class Meta:
        fields = ('match_id', 'player_1_id', 'player_2_id', 'time_stamp', 'winner', 'loser', 'status')


# Points Schema
class PointsSchema(ma.Schema):
    class Meta:
        fields = ('point_id', 'match_id', 'point_num', 'server_id', 'receiver_id', 'server_sets', 'receiver_sets',
                  'server_games', 'receiver_games', 'server_score', 'receiver_score', 'first_serve_outcome',
                  'second_serve_outcome', 'winner_id')


# Use query parameters
# login API
# header for every request will include header "basic auth". Verify before you run code.


# Init Single Schemas
user_schema = UserSchema()
match_schema = MatchSchema()
point_schema = PointsSchema()


# Init Multiple Schemas
users_schema = UserSchema(many=True)
matches_schema = MatchSchema(many=True)
points_schema = PointsSchema(many=True)


# When first starting the db:
with app.app_context():
    #db.drop_all()
    db.create_all()


@app.route('/')
def homepage():
    return "Home"


# Get all users
@app.route('/user', methods=['GET'])
def get_users():
    all_users = User.query.all()
    result = users_schema.dump(all_users)
    return jsonify(result)


# Get single users
@app.route('/user/<int:id>', methods=['GET'])
def get_user(id):
    user = User.query.get(id)
    result = user_schema.jsonify(user)
    return result


# Get single users by name
@app.route('/user/<string:name>', methods=['GET'])
def get_user_by_name(name):
    user = User.query.filter(User.username == name).all()[0]
    result = user_schema.jsonify(user)
    return result


@app.route('/user', methods=['POST'])
def add_user():
    username = request.json['username']
    password = request.json['password']
    email = request.json['email']

    new_user = User(username, password, email)

    db.session.add(new_user)
    db.session.commit()

    return user_schema.jsonify(new_user)


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


@app.route('/match', methods=['GET'])
def list_matches():
    matches = Match.query.all()
    result = matches_schema.dump(matches)
    return jsonify(result)


@app.route('/match/<int:id>', methods=['GET'])
def get_match(id):
    match_list = Match.query.filter(Match.match_id == id).all()
    result = matches_schema.dump(match_list)
    return jsonify(result)


@app.route('/match/<int:id')


@app.route('/match/<int:id1>/<int:id2>', methods=['GET'])
def get_matches(id1, id2):
    matches = Match.query.filter(
        or_(
            and_(Match.server == id1, Match.receiver == id2),
            and_(Match.server == id2, Match.receiver == id1)
        )
    ).all()

    return matches_schema.jsonify(matches)


# Add match
@app.route('/match', methods=['POST'])
def add_match():
    player_1_id = request.json['player_1_id']
    player_2_id = request.json['player_2_id']
    time_stamp = request.json['time_stamp']
    winner = request.json['winner']
    loser = request.json['loser']

    new_match = Match(player_1_id, player_2_id, time_stamp, winner, loser)
    db.session.add(new_match)
    db.session.commit()

    return match_schema.jsonify(new_match)







if __name__ == '__main__':
    app.run(debug=True)
