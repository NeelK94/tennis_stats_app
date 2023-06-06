from flask import Flask, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_, and_
from flask_marshmallow import Marshmallow
from marshmallow import validates, ValidationError, fields
import os
from datetime import datetime, timezone
from passlib.hash import sha256_crypt

from flask_jwt_extended import create_access_token, get_jwt
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

# Init app
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))  # make the base directory same as this file location
# Database and JWT
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = "e7a627480fb8f3fc782f456d63653256109efc93418442bbb643c16ab461461c" # Generate a new secret key before use
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


# User Class/Model

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    first_name = db.Column(db.String(40), nullable=False)
    surname = db.Column(db.String(40), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String, nullable=False)

    def __init__(self, username, first_name, surname, password, email):
        self.username = username
        self.first_name = first_name
        self.surname = surname
        self.password = password
        self.email = email

    # Verify if a given password is correct
    def verify_password(self, given_pass):
        verification = sha256_crypt.verify(given_pass, self.password)
        return verification


class Friendship(db.Model):
    friendship_id = db.Column(db.Integer, primary_key=True)
    requesterId = db.Column(db.Integer)
    addresseeId = db.Column(db.Integer)
    statusCode = db.Column(db.String)
    statusSpecifierId = db.Column(db.Integer)

    def __init__(self, requesterId, addresseeId, statusCode):
        self.requesterId = requesterId
        self.addresseeId = addresseeId
        self.statusCode = statusCode  # Requested (R), Accepted (A), Blocked (B)
        self.statusSpecifierId = requesterId


# Match Class/Model

class Match(db.Model):
    match_id = db.Column(db.Integer, primary_key=True)
    player_1_id = db.Column(db.Integer, nullable=False)  # player_1 is always the player submitting the game.
    player_2_id = db.Column(db.Integer, nullable=False)
    time_stamp = db.Column(db.String, nullable=False)  # CHANGE TO DATETIME!!!
    winner = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String, nullable=False)  # Unsent, Sent, Verified, Declined - determined by p2

    def __init__(self, player_1_id, player_2_id, time_stamp, winner):
        self.player_1_id = player_1_id
        self.player_2_id = player_2_id
        self.time_stamp = time_stamp
        self.winner = winner
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
    id = fields.Integer(dump_only=True)
    username = fields.String(required=True)
    first_name = fields.String(required=True)
    surname = fields.String(required=True)
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

    @validates('first_name')
    def validate_name(self, value):
        if not value:
            raise ValidationError('Name is required')
        return value

    @validates('surname')
    def validate_surname(self, value):
        if not value:
            raise ValidationError('Surname is required')
        return value

    @validates('password')
    def validate_password(self, value):
        if not value:
            raise ValidationError('Password is required')
        return value


# Match Schema

class MatchSchema(ma.Schema):
    class Meta:
        fields = ('match_id', 'player_1_id', 'player_2_id', 'time_stamp', 'winner', 'status')
        ordered = True


# Points Schema

class PointsSchema(ma.Schema):
    class Meta:
        fields = ('point_id', 'match_id', 'point_num', 'server_id', 'receiver_id', 'server_sets', 'receiver_sets',
                  'server_games', 'receiver_games', 'server_score', 'receiver_score', 'first_serve_outcome',
                  'second_serve_outcome', 'winner_id')
        ordered = True


class FriendshipSchema(ma.Schema):
    friendship_id = fields.Int(dump_only=True)
    requesterId = fields.Int(required=True)
    addresseeId = fields.Int(required=True)
    statusCode = fields.String(required=True)
    statusSpecifierId = fields.Int(required=True)

    @validates('statusCode')
    def validate_friend_status(self, value):
        if not value:
            raise ValidationError('Friendship status code is required')
        if value not in ['R', 'A', 'B']:
            raise ValidationError('That is an invalid friendship status code')
        return value


# Init Single Schemas
user_schema = UserSchema()
match_schema = MatchSchema()
point_schema = PointsSchema()
friend_schema = FriendshipSchema()

# Init Multiple Schemas
users_schema = UserSchema(many=True)
matches_schema = MatchSchema(many=True)
points_schema = PointsSchema(many=True)
friends_schema = FriendshipSchema(many=True)

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


# get stats for a given user id from an already filtered view of the Points table.
def get_detailed_stats(data, id):
    total_points_played = len(
        data.filter(
            or_(Points.server_id == id, Points.receiver_id == id)
        ).all()
    )
    total_points_won = len(
        data.filter(
            Points.winner_id == id
        ).all()
    )
    first_serve_count = len(data.filter(Points.server_id == id).all())
    second_serve_count = len(
        data.filter(
            and_(Points.server_id == id, Points.second_serve_outcome != "Null")
        ).all()
    )
    first_serve_in = len(
        data.filter(
            and_(Points.server_id == id, Points.first_serve_outcome != "Fault")
        ).all()
    )
    second_serve_in = len(
        data.filter(
            and_(Points.server_id == id, Points.second_serve_outcome != "Fault", Points.second_serve_outcome != "Null")
        ).all()
    )
    first_serve_won = len(
        data.filter(
            and_(Points.server_id == id, Points.first_serve_outcome != "Fault", Points.winner_id == id)
        ).all()
    )
    second_serve_won = len(
        data.filter(
            and_(Points.server_id == id, Points.second_serve_outcome != "Fault", Points.second_serve_outcome != "Null",
                 Points.winner_id == id)
        ).all()
    )
    ace_count = len(
        data.filter(
            and_(Points.server_id == id,
                 or_(Points.first_serve_outcome == "Ace", Points.second_serve_outcome == "Ace")
                 )
        ).all()
    )
    double_fault_count = len(
        data.filter(
            and_(Points.server_id == id, Points.first_serve_outcome == "Fault", Points.second_serve_outcome == "Fault")
        ).all()
    )
    service_games_played = len(
        data.filter(
            and_(
                Points.server_id == id,
                or_(Points.server_score == "Win", Points.receiver_score == "Win")
            )
        ).all()
    )
    receiving_games_played = len(
        data.filter(
            and_(
                Points.receiver_id == id,
                or_(Points.server_score == "Win", Points.receiver_score == "Win")
            )
        ).all()
    )
    service_games_won = len(
        data.filter(
            and_(Points.server_id == id, Points.server_score == "Win")
        ).all()
    )
    receiving_games_won = len(
        data.filter(
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


# get summary stats for a given user id
def get_summary_stats(data, user_id):
    matches = data.filter(
        or_(Match.player_1_id == user_id, Match.player_2_id == user_id)
    ).all()

    total_matches = len(matches)
    matches_won = data.filter(Match.winner == user_id).all()
    total_wins = len(matches_won)

    if total_matches == 0:
        win_percentage = 0
    else:
        win_percentage = (total_wins / total_matches) * 100

    return {'Matches played': total_matches, 'Matches won': total_wins, 'Win %': win_percentage}


# Check if games need verifying by the user
def pending_verifications(id):
    matches = Match.query.filter(
        and_(Match.player_2_id == id, Match.status == "Sent")
    ).all()
    return matches


@app.route('/')
@jwt_required(optional=True)
def homepage():
    current_user = get_jwt_identity()
    if not current_user:
        return "Welcome! Please log in or create an account."
    user_details = User.query.get(current_user)
    to_verify = len(pending_verifications(current_user))
    return f"Hello {user_details.username}! You are logged in. \nYou have {to_verify} matches to verify."


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
    jti = get_jwt()["jti"]
    now = datetime.now(timezone.utc)
    db.session.add(TokenBlocklist(jti=jti, created_at=now))
    db.session.commit()
    return response, 200


@app.route('/account', methods=['POST'])
def create_account():
    username = request.json['username']
    first_name = request.json['first_name']
    surname = request.json['surname']
    password = request.json['password']
    email = request.json['email']

    # Hash password before creating user object
    hash_pass = sha256_crypt.hash(password)

    # Catch any table validation errors before creating user
    try:
        user_schema.load(request.json)
    except ValidationError as err:
        return jsonify({'error': err.messages}), 400

    new_user = User(username, first_name, surname, hash_pass, email)

    db.session.add(new_user)
    db.session.commit()

    return user_schema.jsonify(new_user)


# Add friendships test
@app.route('/friendships/new/<id_2>', methods=['POST'])
@jwt_required()
def add_friend(id_2):
    id_1 = get_jwt_identity()
    existing = Friendship.query.with_entities(Friendship.statusCode).filter(
        or_(
            and_(Friendship.requesterId == id_1, Friendship.addresseeId == id_2),
            and_(Friendship.requesterId == id_2, Friendship.addresseeId == id_1)
        )
    ).all()

    if existing:
        if existing[0][0] == "R":
            return "You have already requested a friendship with this person, please wait for them to respond"
        elif existing[0][0] == "A":
            return "You are already friends with this person"
        elif existing[0][0] == "B":
            return "This friendship is blocked"
    new_friendship = Friendship(id_1, id_2, "R")
    db.session.add(new_friendship)
    db.session.commit()
    return friend_schema.jsonify(new_friendship)


# get friends list
@app.route('/friendships', methods=['GET'])
@jwt_required()
def get_friends():
    id = get_jwt_identity()
    friends_list = set()
    friends_1 = Friendship.query.filter(
        and_(Friendship.requesterId == id, Friendship.statusCode == 'R')  # CHANGE TO A
    ).all()
    friends_2 = Friendship.query.filter(
        and_(Friendship.addresseeId == id, Friendship.statusCode == 'R')  # CHANGE TO A
    ).all()

    for f in friends_1:
        friends_list.add(f.addresseeId)
    for f in friends_2:
        friends_list.add(f.requesterId)
    return jsonify(list(friends_list))


@app.route('/friendships/remove/<f_id>', methods=['DELETE'])
@jwt_required()
def remove_friend(f_id):
    id = get_jwt_identity()
    friendship = Friendship.query.get(f_id)
    if friendship.addresseeId == id or friendship.requesterId == id:
        db.session.delete(friendship)
        db.session.commit()
        result = friend_schema.jsonify(friendship)
    else:
        result = "Unable to perform action"

    return result


# Get pending friend requests
@app.route('/friendships/requests', methods=['GET'])
@jwt_required()
def friend_requests():
    id = get_jwt_identity()
    friends = Friendship.query.filter(
        and_(Friendship.addresseeId == id, Friendship.statusCode == 'R')  # CHANGE TO A
    ).all()

    result = friends_schema.jsonify(friends)

    return result


@app.route('/friendships/accept/<f_id>', methods=['PUT'])
@jwt_required()
def accept_request(f_id):
    id = get_jwt_identity()
    request = Friendship.query.get(f_id)
    if request.addresseeId == id and request.statusCode == "R":
        request.statusCode = "A"
    else:
        return "Unable to perform action"

    return "Friend request accepted!"


@app.route('/friendships/block/<their_id>', methods=['PUT', 'POST'])
@jwt_required()
def block_user(their_id):
    my_id = get_jwt_identity()
    existing = Friendship.query.with_entities(Friendship.friendship_id).filter(
        or_(
            and_(Friendship.requesterId == their_id, Friendship.addresseeId == my_id),
            and_(Friendship.requesterId == my_id, Friendship.addresseeId == their_id)
        )
    ).all()

    if existing:
        friendship = Friendship.query.get(existing[0][0])
        friendship.statusCode = "B"
    else:
        blocked = Friendship(my_id, their_id, "B")
        db.session.add(blocked)
        db.session.commit()

    db.session.commit()

    return "User blocked"


# Edit account
@app.route('/account/update', methods=['PUT'])
@jwt_required()
def update_user():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    username = request.json['username']
    first_name = request.json['first_name']
    surname = request.json['surname']
    password = request.json['password']
    hash_pass = sha256_crypt.hash(password)
    email = request.json['email']

    user.username = username
    user.first_name = first_name
    user.surname = surname
    user.password = hash_pass
    user.email = email

    new_user = User(username, first_name, surname, hash_pass, email)

    db.session.commit()

    return user_schema.jsonify(new_user)


# Delete account
@app.route('/account/delete', methods=['DELETE'])
@jwt_required()
def delete_user():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    jti = get_jwt()["jti"]

    db.session.delete(user)
    db.session.commit()

    now = datetime.now(timezone.utc)
    db.session.add(TokenBlocklist(jti=jti, created_at=now))
    db.session.commit()

    result = user_schema.jsonify(user)

    return result


# region USERS

# Get all users
@app.route('/user', methods=['GET'])
@jwt_required()
def get_users():
    all_users = User.query.all()
    result = users_schema.dump(all_users)
    return jsonify(result)


# Get a single user by username
@app.route('/user/search', methods=['GET'])
def user_search():
    username = request.args.get('username')
    user = User.query.filter(User.username == username).all()[0]

    result = user_schema.jsonify(user)

    return result


# Get summary stats for user
@app.route('/user/stats/summary', methods=['GET'])
@jwt_required()
def get_summary():
    user_id = get_jwt_identity()
    data = Match.query.filter(
        or_(Match.player_1_id == user_id, Match.player_2_id == user_id)
    )

    stats = get_summary_stats(data, user_id)

    return stats


# Get detailed stats for user
@app.route('/user/stats/detailed', methods=['GET'])
@jwt_required()
def get_details():
    id = get_jwt_identity()
    data = Points.query.filter(
        or_(Points.server_id == id, Points.receiver_id == id)
    )
    stats = get_detailed_stats(data, id)
    return stats


# get head-to-head stats
@app.route('/stats/head-to-head/<p1>/<p2>')
def vs_stats(p1, p2):
    points_data = Points.query.filter(
        or_(
            and_(Points.server_id == p1, Points.receiver_id == p2),
            and_(Points.server_id == p2, Points.receiver_id == p1)
        )
    )
    p1_stats = get_detailed_stats(points_data, p1)
    p2_stats = get_detailed_stats(points_data, p2)

    return [(p1, p1_stats), (p2, p2_stats)]


# compare user stats overall
@app.route('/stats/comparison/<p1>/<p2>')
def compare_stats(p1, p2):
    p1_summary_data = Match.query.filter(
        or_(Match.player_1_id == p1, Match.player_2_id == p1)
    )
    p2_summary_data = Match.query.filter(
        or_(Match.player_1_id == p2, Match.player_2_id == p2)
    )

    p1_points_data = Points.query.filter(
        or_(Points.server_id == p1, Points.receiver_id == p1)
    )
    p2_points_data = Points.query.filter(
        or_(Points.server_id == p2, Points.receiver_id == p2)
    )

    p1_summary_stats = get_summary_stats(p1_summary_data, p1)
    p2_summary_stats = get_summary_stats(p2_summary_data, p2)

    p1_detailed_stats = get_detailed_stats(p1_points_data, p1)
    p2_detailed_stats = get_detailed_stats(p2_points_data, p2)

    results = {"p1_id": p1, "p1_summary": p1_summary_stats, "p1_details": p1_detailed_stats,
               "p2_id": p2, "p2_summary": p2_summary_stats, "p2_details": p2_detailed_stats}
    return jsonify(results)


# endregion USERS

# region MATCHES

# List all matches
@app.route('/match', methods=['GET'])
def list_matches():
    matches = Match.query.all()
    result = matches_schema.jsonify(matches)
    return result


# Get current users matches
@app.route('/match/mymatches', methods=['GET'])
@jwt_required()
def my_matches():
    user_id = get_jwt_identity()
    matches = Match.query.filter(
        or_(Match.player_1_id == user_id, Match.player_2_id == user_id)
    ).all()
    result = matches_schema.jsonify(matches)
    return result


# get stats of a specific match
@app.route('/match/<match_id>', methods=['GET'])
def match_stats(match_id):
    match_data = Points.query.filter(Points.match_id == match_id)
    match_result = Match.query.get(match_id)
    if not match_result:
        return "Match not found"
    player_1_id = match_result.player_1_id
    player_2_id = match_result.player_2_id

    p1_stats = get_detailed_stats(match_data, player_1_id)
    p2_stats = get_detailed_stats(match_data, player_2_id)

    return [(player_1_id, p1_stats), (player_2_id, p2_stats)]


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

    new_match = Match(player_1_id, player_2_id, time_stamp, winner)
    db.session.add(new_match)
    db.session.commit()

    return match_schema.jsonify(new_match)


# Update match status
@app.route('/match/verify/<match_id>', methods=['PUT'])
@jwt_required()
def update_status(match_id):
    user_id = get_jwt_identity()
    match = Match.query.get(match_id)
    if not match:
        return "Match not found"
    if (match.player_2_id != user_id) or (match.status != "Sent"):
        return "You cannot verify this match."
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


if __name__ == '__main__':
    app.run(debug=True)
