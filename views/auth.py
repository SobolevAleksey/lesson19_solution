from flask import request
from flask_restx import Namespace, Resource

from implemented import auth_service

auth_ns = Namespace('auth')


@auth_ns.route('/')
class AuthView(Resource):
    def get(self):
        data = request.json
        token = data.get('refresh_token')
        tokens = auth_service.approve_refresh_token(token)
        return tokens, 201

    def post(self):
        req_json = request.json
        username = req_json.get('username')
        password = req_json.get('password')
        if None in [username, password]:
            return "", 404

        tokens = auth_service.generate_token(username, pssword)
        return tokens, 201
