from flask import Flask
from flask_restful import Resource, Api, reqparse
from database import APIDatabase, UsernameException

app = Flask(__name__)
api = Api(app)
db = APIDatabase()


class Auth(Resource):
	def get(self):
		"""Login, return a token"""
		parser = reqparse.RequestParser()
		parser.add_argument("username", help="Must provide username to log in with", required=True)
		parser.add_argument("password", help="Must provide password to log in with", required=True)
		args = parser.parse_args()
		try:
			if db.authenticate(args["username"], args["password"]):
				return "Success", 200
			else:
				return "Bad login", 401
		except UsernameException:
			return "Bad username", 401

	def post(self):
		"""Register new user"""
		parser = reqparse.RequestParser()
		parser.add_argument("username", help="Must provide username to register", required=True)
		parser.add_argument("password", help="Must provide password to set for new user", required=True)
		parser.add_argument("term", help="Provide term (A,B,C,D) that user is registering from", required=True)
		parser.add_argument("year", help="Provide year that user is registering from", required=True)
		parser.add_argument("team", help="Provide letter of team that user is registering from", required=True)

		args = parser.parse_args()
		username = args["username"]
		password = args["password"]
		term = args["term"]
		year = args["year"]
		team = args["team"]
		try:
			db.registerUser(username, password, term, year, team)
		except UsernameException:
			return "Username exists", 403
		return "Success", 200

	def delete(self):
		"""Delete user, requires password as confirmation"""
		parser = reqparse.RequestParser()
		parser.add_argument("username", help="Must provide username to log in with", required=True)
		parser.add_argument("password", help="Must provide password to log in with", required=True)
		args = parser.parse_args()
		try:
			if db.authenticate(args["username"], args["password"]):
				db.deleteUser(args["username"])
				return "Success", 200
			else:
				return "Bad login", 401
		except UsernameException:
			return "Bad username", 401


api.add_resource(Auth, "/auth")

if __name__ == "__main__":
	app.run(port="5000")
