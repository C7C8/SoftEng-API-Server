from flask import Flask
from flask_restful import Resource, Api, reqparse
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, JWTManager
import datetime
from apiDB import APIDatabase

app = Flask(__name__)
api = Api(app)
db = APIDatabase()
with open("key.txt", "r") as keyfile:
	app.config["JWT_SECRET_KEY"] = keyfile.read()
jwt = JWTManager(app)


class Auth(Resource):
	def get(self):
		"""Login, return a token"""
		parser = reqparse.RequestParser()
		parser.add_argument("username", help="Must provide username to log in with", type=str, required=True)
		parser.add_argument("password", help="Must provide password to log in with", type=str, required=True)
		args = parser.parse_args()
		if not db.authenticate(args["username"], args["password"]):
			return {"message": "Incorrect username or password"}, 401
		expires = datetime.timedelta(minutes=20)
		atoken = create_access_token(args["username"], expires_delta=expires)
		rtoken = create_refresh_token(args["username"], expires_delta=expires)
		return {
			"message": "Logged in as {}".format(args["username"]),
			"access_token": atoken,
			"refresh_token": rtoken
		}, 200

	def post(self):
		"""Register new user"""
		parser = reqparse.RequestParser()
		parser.add_argument("username", help="Must provide username to register", required=True, type=str)
		parser.add_argument("password", help="Must provide password to set for new user", required=True, type=str)
		parser.add_argument("term", help="Provide term (A,B,C,D) that user is registering from", required=True, type=str)
		parser.add_argument("year", help="Provide year that user is registering from", required=True, type=int)
		parser.add_argument("team", help="Provide letter of team that user is registering from", required=True, type=str)

		args = parser.parse_args()
		username = args["username"]
		password = args["password"]
		term = args["term"]
		year = args["year"]
		team = args["team"]
		if not db.registerUser(username, password, term, year, team):
			return {"message": "Registration failed"}, 403
		return {"message": "Successfully registered as user {}".format(username)}, 200

	def delete(self):
		"""Delete user, requires password as confirmation"""
		parser = reqparse.RequestParser()
		parser.add_argument("username", help="Must provide username to log in with", required=True, type=str)
		parser.add_argument("password", help="Must provide password to log in with", required=True, type=str)
		args = parser.parse_args()
		if db.authenticate(args["username"], args["password"]):
			db.deleteUser(args["username"])
			return {"message": "Successfully deleted user {}".format(args["username"])}, 200
		else:
			return {"message": "Incorrect username or password"}, 401


api.add_resource(Auth, "/auth")

if __name__ == "__main__":
	app.run(port="5000")
