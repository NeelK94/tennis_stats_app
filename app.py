from flask import Flask, request, jsonify, session, request, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_, and_
from flask_marshmallow import Marshmallow
from marshmallow import validates, ValidationError, fields
import os
from datetime import datetime, timedelta, timezone
import uuid
import redis
from passlib.hash import sha256_crypt
from functools import wraps

from flask_jwt_extended import create_access_token, get_jwt, unset_jwt_cookies, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

# Init app
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))  # make the base directory same as this file location
# Database and JWT
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = "e7a627480fb8f3fc782f456d63653256109efc93418442bbb643c16ab461461c"
jwt = JWTManager(app)
# Init db
db = SQLAlchemy(app)
# Init ma
ma = Marshmallow(app)


# Token blocklist

class TokenBlocklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False)


# Callback function to check if a JWT exists in the database blocklist
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload: dict) -> bool:
    jti = jwt_payload["jti"]
    token = db.session.query(TokenBlocklist.id).filter_by(jti=jti).scalar()

    return token is not None


# User Class/Model

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(120))
    email = db.Column(db.String, nullable=False)

    def __init__(self, username, password, email):
        self.username = username
        self.password = password
        self.email = email

    # Verify if a given password is equal to the actual password
    def verify_password(self, given_pass):
        verification = sha256_crypt.verify(given_pass, self.password)
        print(verification)
        return verification


# Match Class/Model

class Match(db.Model):
    match_id = db.Column(db.Integer, primary_key=True)
    player_1_id = db.Column(db.Integer)
    player_2_id = db.Column(db.Integer)
    time_stamp = db.Column(db.String)  # CHANGE TO DATETIME!!!
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
    # class Meta:
    #    fields = ('id', 'username', 'password', 'email')
    #    ordered = True

    id = fields.Integer(dump_only=True)
    username = fields.String(required=True)
    password = fields.String(required=True)
    email = fields.String(required=True)

    @validates('username')
    def validate_username(self, value):
        if not value:
            raise ValidationError('Username is required')
        if len(value) < 4 or len(value) > 50:
            raise ValidationError('Username must be between 4 and 50 characters')
        if valid_username(value) is False:
            raise ValidationError('Username is already taken')
        return value

    @validates('email')
    def validate_email(self, value):
        if not value:
            raise ValidationError('Email is required')
        return value

    @validates('password')
    def validate_password(self, value):
        if not value:
            raise ValidationError('Password is required')
        return value


# Match Schema

class MatchSchema(ma.Schema):
    class Meta:
        fields = ('match_id', 'player_1_id', 'player_2_id', 'time_stamp', 'winner', 'loser', 'status')
        ordered = True


# Points Schema

class PointsSchema(ma.Schema):
    class Meta:
        fields = ('point_id', 'match_id', 'point_num', 'server_id', 'receiver_id', 'server_sets', 'receiver_sets',
                  'server_games', 'receiver_games', 'server_score', 'receiver_score', 'first_serve_outcome',
                  'second_serve_outcome', 'winner_id')
        ordered = True


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
    # db.drop_all()
    db.create_all()


def valid_username(uname):
    query = User.query.filter(User.username == uname).all()
    if query:
        return False
    else:
        return True


@app.route('/')
@jwt_required(optional=True)
def homepage():
    current_user = get_jwt_identity()
    if not current_user:
        return "Welcome! Please log in or create an account."
    return "Hello! You are logged in."


@app.route('/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']

    try:
        user = User.query.filter(User.username == username).all()[0]
    except IndexError:
        return jsonify({'message': "Username not found"})

    if user.verify_password(password):
        token = create_access_token(identity=user.id)
        return jsonify({'token': token})

    return make_response('could not verify', 403, {'WWW.Authentication': 'Basic realm: "Incorrect Credentials"'})


@app.route('/logout', methods=['DELETE'])
@jwt_required()
def logout():
    # revoke token from user
    response = jsonify({'message': 'Successfully logged out'})
    #unset_jwt_cookies(response)
    jti = get_jwt()["jti"]
    now = datetime.now(timezone.utc)
    db.session.add(TokenBlocklist(jti=jti, created_at=now))
    db.session.commit()
    return response, 200



# region USERS

# Get all users
@app.route('/user', methods=['GET'])
@jwt_required()
def get_users():
    all_users = User.query.all()
    result = users_schema.dump(all_users)
    test = get_jwt_identity()
    print(test)
    print(get_jwt())
    return jsonify(result)


# Get a single user by username
@app.route('/user', methods=['GET'])
def user_search():
    username = request.args.get('username')
    user = User.query.filter(User.username == username).all()[0]

    result = user_schema.jsonify(user)

    return result


# Get single user by id
@app.route('/user/<int:id>', methods=['GET'])
def get_user(id):
    user = User.query.get(id)
    result = user_schema.jsonify(user)
    return result


@app.route('/user', methods=['POST'])
def add_user():
    username = request.json['username']
    password = request.json['password']
    email = request.json['email']

    # Hash password before creating user object
    hash_pass = sha256_crypt.hash(password)

    # Catch any table validation errors before creating user
    try:
        user_schema.load(request.json)
    except ValidationError as err:
        return jsonify({'error': err.messages}), 400

    new_user = User(username, hash_pass, email)

    db.session.add(new_user)
    db.session.commit()

    return user_schema.jsonify(new_user)


# Update user
## For production this would be more complex where you can change one thing at a time
@app.route('/user/<id>', methods=['PUT'])
def update_user(id):
    user = User.query.get(id)

    username = request.json['username']
    password = request.json['password']
    hash_pass = sha256_crypt.hash(password)
    email = request.json['email']

    user.username = username
    user.password = hash_pass
    user.email = email

    new_user = User(username, hash_pass, email)

    db.session.commit()  # No need to add before you commit, since it's a PUT

    return user_schema.jsonify(new_user)


# delete user
@app.route('/user/<id>', methods=['DELETE'])
def delete_user(id):
    user = User.query.get(id)
    db.session.delete(user)
    db.session.commit()
    result = user_schema.jsonify(user)
    return result


# endregion USERS

# region MATCHES

# List all matches
@app.route('/match', methods=['GET'])
def list_matches():
    matches = Match.query.all()
    result = matches_schema.dump(matches)
    return jsonify(result)


# Get a match by match_id
@app.route('/match/<match_id>', methods=['GET'])
def get_match(match_id):
    match = Match.query.get(match_id)
    result = match_schema.jsonify(match)
    return result


# Filter matches for one player or a pair of players
@app.route('/match/search', methods=['GET'])
def get_matches():
    p1 = request.args.get('p1')
    p2 = request.args.get('p2')

    if p1 and p2:
        print("Both players given")
        matches = Match.query.filter(
            or_(
                and_(Match.player_1_id == p1, Match.player_2_id == p2),
                and_(Match.player_1_id == p2, Match.player_2_id == p1)
            )
        ).all()

    elif p1:
        print("Only p1 given")
        matches = Match.query.filter(
            or_(Match.player_1_id == p1, Match.player_2_id == p1)
        ).all()

    elif p2:
        print("Only p2 given")
        matches = Match.query.filter(
            or_(Match.player_1_id == p2, Match.player_2_id == p2)
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


# Update match status
@app.route('/match/<match_id>', methods=['PUT'])
def update_status(match_id):
    match = Match.query.get(match_id)
    new_status = request.json['status']

    if new_status not in ['Unsent', 'Sent', 'Verified', 'Declined']:
        return "Invalid status"

    match.status = new_status

    db.session.commit()

    return match_schema.jsonify(match)


# endregion MATCHES

# region POINTS


# Get all points
@app.route('/points', methods=['GET'])
def all_points():
    all_data = Points.query.all()
    result = points_schema.dump(all_data)
    return jsonify(result)


# Filter points by match_id (and eventually other things)
@app.route('/points/filter', methods=['GET'])
def filter_points():
    match_id = request.args.get('match_id')
    points = Points.query.filter(Points.match_id == match_id).order_by(Points.point_num.asc())
    result = points_schema.dump(points)
    return jsonify(result)


# Add a matches points to the points table
@app.route('/points', methods=['POST'])
def add_points():
    match_data = request.get_json()

    rows = points_schema.load(match_data)

    for row in rows:
        new_row = Points(**row)
        db.session.add(new_row)

    db.session.commit()

    return jsonify({'message': 'Rows added successfully'}), 201


# endregion POINTS


@app.route('/user/<id>/overview', methods=['GET'])
def get_summary(id):
    user = User.query.get(id)
    matches = Match.query.filter(
        or_(Match.player_1_id == id, Match.player_2_id == id)
    ).all()

    total_matches = len(matches)
    matches_won = Match.query.filter(Match.winner == id).all()
    total_wins = len(matches_won)

    if total_matches == 0:
        win_percentage = 0
    else:
        win_percentage = (total_wins / total_matches) * 100

    return jsonify({'Matches played': total_matches, 'Matches won': total_wins, 'Win %': win_percentage})


@app.route('/user/<id>/details', methods=['GET'])
def get_details(id):
    user = User.query.get(id)

    total_points_played = len(
        Points.query.filter(
            or_(Points.server_id == id, Points.receiver_id == id)
        ).all()
    )
    total_points_won = len(
        Points.query.filter(
            Points.winner_id == id
        ).all()
    )
    first_serve_count = len(Points.query.filter(Points.server_id == id).all())
    second_serve_count = len(
        Points.query.filter(
            and_(Points.server_id == id, Points.second_serve_outcome != "Null")
        ).all()
    )
    first_serve_in = len(
        Points.query.filter(
            and_(Points.server_id == id, Points.first_serve_outcome != "Fault")
        ).all()
    )
    second_serve_in = len(
        Points.query.filter(
            and_(Points.server_id == id, Points.second_serve_outcome != "Fault", Points.second_serve_outcome != "Null")
        ).all()
    )
    first_serve_won = len(
        Points.query.filter(
            and_(Points.server_id == id, Points.first_serve_outcome != "Fault", Points.winner_id == id)
        ).all()
    )
    second_serve_won = len(
        Points.query.filter(
            and_(Points.server_id == id, Points.second_serve_outcome != "Fault", Points.second_serve_outcome != "Null",
                 Points.winner_id == id)
        ).all()
    )
    ace_count = len(
        Points.query.filter(
            and_(Points.server_id == id,
                 or_(Points.first_serve_outcome == "Ace", Points.second_serve_outcome == "Ace")
                 )
        ).all()
    )
    double_fault_count = len(
        Points.query.filter(
            and_(Points.server_id == id, Points.first_serve_outcome == "Fault", Points.second_serve_outcome == "Fault")
        ).all()
    )
    service_games_played = len(
        Points.query.filter(
            and_(
                Points.server_id == id,
                or_(Points.server_score == "Win", Points.receiver_score == "Win")
            )
        ).all()
    )
    receiving_games_played = len(
        Points.query.filter(
            and_(
                Points.receiver_id == id,
                or_(Points.server_score == "Win", Points.receiver_score == "Win")
            )
        ).all()
    )
    service_games_won = len(
        Points.query.filter(
            and_(Points.server_id == id, Points.server_score == "Win")
        ).all()
    )
    receiving_games_won = len(
        Points.query.filter(
            and_(Points.receiver_id == id, Points.receiver_score == "Win")
        ).all()
    )

    try:
        percentage_points_won = (total_points_won / total_points_played) * 100
    except ZeroDivisionError as e:
        percentage_points_won = "Null"
    try:
        percentage_first_serves_in = (first_serve_in / first_serve_count) * 100
    except ZeroDivisionError as e:
        percentage_first_serves_in = "Null"
    try:
        percentage_first_serve_points_won = (first_serve_won / first_serve_count) * 100
    except ZeroDivisionError as e:
        percentage_first_serve_points_won = "Null"
    try:
        percentage_second_serves_in = (second_serve_in / second_serve_count) * 100
    except ZeroDivisionError as e:
        percentage_second_serves_in = "Null"
    try:
        percentage_second_serve_points_won = (second_serve_won / second_serve_count) * 100
    except ZeroDivisionError as e:
        percentage_second_serve_points_won = "Null"
    try:
        percentage_aces = (ace_count / (first_serve_count + second_serve_count)) * 100
    except ZeroDivisionError as e:
        percentage_aces = "Null"
    try:
        percentage_double_faults = (double_fault_count / (first_serve_count + second_serve_count)) * 100
    except ZeroDivisionError as e:
        percentage_double_faults = "Null"
    try:
        percentage_serve_win = (service_games_won / service_games_played) * 100
    except ZeroDivisionError as e:
        percentage_serve_win = "Null"
    try:
        percentage_receive_win = (receiving_games_won / receiving_games_played) * 100
    except ZeroDivisionError as e:
        percentage_receive_win = "Null"

    result = {
        "Points won %": percentage_points_won,
        "First serves in %": percentage_first_serves_in,
        "Second serves in %": percentage_second_serves_in,
        "First serves won %": percentage_first_serve_points_won,
        "Second serves won %": percentage_second_serve_points_won,
        "Ace %": percentage_aces,
        "Double fault %": percentage_double_faults,
        "Service games win %": percentage_serve_win,
        "receiving games win %": percentage_receive_win

    }

    return result


if __name__ == '__main__':
    app.run(debug=True)
