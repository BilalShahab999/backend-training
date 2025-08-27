from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import datetime
from flask_jwt_extended import create_refresh_token

from middleware.request_logger import log_request
from middleware.response_logger import log_response
from interceptors.before import interceptor_before_request
from interceptors.after import interceptor_after_request

app = Flask(__name__)
app.before_request(log_request)
app.after_request(log_response)

app.before_request(interceptor_before_request)
app.after_request(interceptor_after_request)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = "super-secret-key"  
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=6)

db = SQLAlchemy(app)
jwt = JWTManager(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

with app.app_context():
    db.create_all()

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    if not data or not data.get("username") or not data.get("email") or not data.get("password"):
        return jsonify({"error": "Missing required fields"}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({"error": "Email already registered"}), 400

    hashed_pw = generate_password_hash(data['password'], method="pbkdf2:sha256")
    new_user = User(username=data['username'], email=data['email'], password=hashed_pw)

    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User created successfully!"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get("email") or not data.get("password"):
        return jsonify({"error": "Missing required fields"}), 400

    user = User.query.filter_by(email=data['email']).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    if check_password_hash(user.password, data['password']):

        access_token = create_access_token(identity=str(user.id))
        refresh_token = create_refresh_token(identity=str(user.id))
        return jsonify({
            "message": "Login successful!",
            "access_token": access_token,
            "refresh_token": refresh_token
        }), 200
    else:
        return jsonify({"error": "Invalid password"}), 401
    from flask_jwt_extended import jwt_refresh_token_required

@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)  
def refresh():
    current_user = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user)
    return jsonify({"access_token": new_access_token}), 200

@app.route('/get_user', methods=['GET'])
@jwt_required()
def get_user():
    
    current_user_id = int(get_jwt_identity())
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": user.email
    }), 200


@app.route('/update/<int:id>', methods=['PUT'])
@jwt_required()
def update_user(id):
    current_user_id = int(get_jwt_identity())
    if current_user_id != id:
        return jsonify({"error": "Unauthorized access"}), 403

    data = request.get_json()
    user = User.query.get(id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    if "username" in data:
        user.username = data["username"]
    if "email" in data:
        user.email = data["email"]
    if "password" in data:
        user.password = generate_password_hash(data["password"], method="pbkdf2:sha256")

    db.session.commit()
    return jsonify({"message": "User updated successfully"}), 200

@app.route('/delete/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_user(id):
    current_user_id = int(get_jwt_identity())
    if current_user_id != id:
        return jsonify({"error": "Unauthorized access"}), 403

    user = User.query.get(id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted successfully!"}), 200

if __name__ == "__main__":
    app.run(debug=True)