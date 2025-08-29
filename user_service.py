from models.user_model import User, db

class UserService:
    def __init__(self, db_instance):
        self.db = db_instance

    def get_all_users(self):
        return User.query.all()

    def create_user(self, username, email):
        new_user = User(username=username, email=email)
        self.db.session.add(new_user)
        self.db.session.commit()
        return new_user
