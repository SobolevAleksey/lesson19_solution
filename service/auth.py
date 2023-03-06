import calendar
import datetime
import jwt
from constants import JWT_ALGORITHM, JWT_SECRET
from service.user import UserService


class AuthService:
    def __init__(self, user_service: UserService):
        self.user_service = user_service

    def generate_token(self, username, password, is_refresh=False):
        user = self.user_service.get_by_username(username)
        if user is None:
            raise Exception()  # или abort()

        if not is_refresh:
            if not self.user_service.compare_passwords(user.password, password):
                raise Exception()  # или abort()

        data = {
            'username': user.username,
            'role': user.role
        }

        # Токен на 30 мин
        min30 = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        data["exp"] = calendar.timegm(min30.timetuple())
        access_token = jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGORITHM)
        # Токен на 130 дней
        days130 = datetime.datetime.utcnow() + datetime.timedelta(days=130)
        data["exp"] = calendar.timegm(days130.timetuple())
        refresh_token = jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGORITHM)
        return {"access_token": access_token, "refresh_token": refresh_token}

    def approve_refresh_token(self, refresh_token):
        data = jwt.decode(jwt=refresh_token, key=JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username = data.get('username')

        user = self.user_service.get_by_username(username=username)
        if user is None:
            raise Exception()
        return self.generate_token(username, user.password, is_refresh=True)
