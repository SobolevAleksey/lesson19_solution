from flask import request
from flask_restx import Resource, Namespace

from dao.model.user import UserSchema
from implemented import user_service

user_ns = Namespace('users')

user_schema = UserSchema()
users_schema = UserSchema(many=True)


@user_ns.route('/')
class UsersView(Resource):
    def get(self):
        all_users = user_service.get_all()
        res = users_schema.dump(all_users)
        return res, 200

    def post(self):
        req_json = request.json
        user = user_service.create(req_json)
        return "", 201 # {"location": f"/users/{user.id}"}


@user_ns.route('/<int:uid>')
class UserView(Resource):
    def put(self, uid):
        req_json = request.json
        if "id" not in req_json:
            req_json["id"] = uid
        user_service.update(req_json)
        return "", 204

    def get(self, uid):
        user = user_service.get_one(uid)
        user_data = users_schema.dump(user)
        return user_data, 200

    def delete(self, uid):
        user_service.delete(uid)
        return '', 204