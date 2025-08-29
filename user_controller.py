from flask import Blueprint, request, jsonify
from services.user_service import UserService
from models.user_model import db

user_bp = Blueprint("user_bp", __name__)
user_service = UserService(db)

@user_bp.route("/users", methods=["GET"])
def get_users():
    users = user_service.get_all_users()
    return jsonify([{"id": u.id, "username": u.username, "email": u.email} for u in users])

@user_bp.route("/users", methods=["POST"])
def create_user():
    data = request.get_json()
    new_user = user_service.create_user(data["username"], data["email"])
    return jsonify({"id": new_user.id, "username": new_user.username, "email": new_user.email})
