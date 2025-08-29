from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, create_refresh_token
import datetime
from flask_injector import FlaskInjector
from injector import Binder, singleton
from models.user_model import db

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

db.init_app(app)
with app.app_context():
    db.create_all()

db = SQLAlchemy()
jwt = JWTManager()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class UserService:
    def __init__(self, db: SQLAlchemy):
        self.db = db

    def create_user(self, username, email, password):
        hashed_pw = generate_password_hash(password, method="pbkdf2:sha256")
        new_user = User(username=username, email=email, password=hashed_pw)
        self.db.session.add(new_user)
        self.db.session.commit()
        return new_user

    def get_user_by_email(self, email):
        return User.query.filter_by(email=email).first()

    def get_user_by_id(self, user_id):
        return User.query.get(user_id)

    def update_user(self, user, data):
        if "username" in data:
            user.username = data["username"]
        if "email" in data:
            user.email = data["email"]
        if "password" in data:
            user.password = generate_password_hash(data["password"], method="pbkdf2:sha256")
        self.db.session.commit()
        return user

    def delete_user(self, user):
        self.db.session.delete(user)
        self.db.session.commit()

@app.route('/signup', methods=['POST'])
def signup(user_service: UserService):
    data = request.get_json()
    if not data or not data.get("username") or not data.get("email") or not data.get("password"):
        return jsonify({"error": "Missing required fields"}), 400

    if user_service.get_user_by_email(data['email']):
        return jsonify({"error": "Email already registered"}), 400

    user_service.create_user(data['username'], data['email'], data['password'])
    return jsonify({"message": "User created successfully!"}), 201

@app.route('/login', methods=['POST'])
def login(user_service: UserService):
    data = request.get_json()
    if not data or not data.get("email") or not data.get("password"):
        return jsonify({"error": "Missing required fields"}), 400

    user = user_service.get_user_by_email(data['email'])
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


@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user)
    return jsonify({"access_token": new_access_token}), 200

@app.route('/get_user', methods=['GET'])
@jwt_required()
def get_user(user_service: UserService):
    current_user_id = int(get_jwt_identity())
    user = user_service.get_user_by_id(current_user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "id": user.id,
        "username": user.username,
        "email": user.email
    }), 200


@app.route('/update/<int:id>', methods=['PUT'])
@jwt_required()
def update_user(id, user_service: UserService):
    current_user_id = int(get_jwt_identity())
    if current_user_id != id:
        return jsonify({"error": "Unauthorized access"}), 403

    data = request.get_json()
    user = user_service.get_user_by_id(id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    user_service.update_user(user, data)
    return jsonify({"message": "User updated successfully"}), 200


@app.route('/delete/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_user(id, user_service: UserService):
    current_user_id = int(get_jwt_identity())
    if current_user_id != id:
        return jsonify({"error": "Unauthorized access"}), 403

    user = user_service.get_user_by_id(id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    user_service.delete_user(user)
    return jsonify({"message": "User deleted successfully!"}), 200



def configure(binder: Binder):
    db.init_app(app)
    jwt.init_app(app)
    with app.app_context():
        db.create_all()

    binder.bind(SQLAlchemy, to=db, scope=singleton)
    binder.bind(UserService, to=UserService(db), scope=singleton)


FlaskInjector(app=app, modules=[configure])


app.register_blueprint(user_bp, url_prefix="/api")

if __name__ == "__main__":
    app.run(debug=True)