from flask import Flask, request
from flask_restful import Resource, Api
from json import dumps
from flask import jsonify
import bcrypt

app = Flask(__name__)
api = Api(app)


class Login(Resource):
	def get(self):
		if len(request.get_data()) == 0:
			return None, 400
		username = request.json["username"]
		password = request.json["password"]
		hashed = bcrypt.hashpw("test", bcrypt.gensalt())
		print("Username: " + username)
		print("Password: " + password)
		print("Hashedpw: " + hashed)
		if bcrypt.checkpw(password, hashed):
			print("Password matches!")
		else:
			print("Password doesn't match!")


api.add_resource(Login, "/login")

if __name__ == "__main__":
	app.run(port="5000")
