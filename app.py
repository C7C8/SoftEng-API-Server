from flask import Flask, request, jsonify
from flask_restful import Resource, Api
from database import APIDatabase, UsernameException

app = Flask(__name__)
api = Api(app)
db = APIDatabase()


class Auth(Resource):
	def get(self):
		"""Get a token"""
		request.get_data()
		if len(request.args) == 0:
			return None, 400

		username = request.args["username"]
		password = request.args["password"]
		try:
			if db.authenticate(username, password):
				return "Success", 200
			else:
				return "Bad login", 401
		except UsernameException:
			return "Bad username", 401

	def post(self):
		"""Register new user"""
		request.get_data()
		if len(request.json) == 0:
			return None, 400

		username = request.json["username"]
		password = request.json["password"]
		term = request.json["term"]
		year = request.json["year"]
		team = request.json["team"]
		try:
			db.registerUser(username, password, term, year, team)
		except UsernameException:
			return "Username exists", 403
		return "Success", 200

	def delete(self):
		request.get_data()
		if len(request.args) == 0:
			return None, 400

		username = request.args["username"]
		password = request.args["password"]
		try:
			if db.authenticate(username, password):
				db.deleteUser(username)
				return "Success", 200
			else:
				return "Bad login", 401
		except UsernameException:
			return "Bad username", 401


api.add_resource(Auth, "/auth")

if __name__ == "__main__":
	app.run(port="5000")
