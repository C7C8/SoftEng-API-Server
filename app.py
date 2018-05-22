import os
import datetime
from json import loads
from flask import Flask
from flask_restful.reqparse import RequestParser
from flask_restful import Resource, Api
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, \
	get_jwt_identity, JWTManager

from apiDB import APIDatabase

# Set up flask
app = Flask(__name__)
api = Api(app)

# Load configuration
conf = {
	"jwt-key": "DEFAULT PRIVATE KEY",
	"img-dir": "img",
	"jar-dir": "jar",
	"json-output": "apilist.json"
}
try:
	with open("conf.json", "r") as file:
		conf = loads(file.read())
except FileNotFoundError:
	print("Couldn't load server conf 'conf.json', using default settings! This is extremely dangerous!")

app.config["JWT_SECRET_KEY"] = conf["jwt-key"]
jwt = JWTManager(app)
if not os.path.exists(conf["img-dir"]):
	os.makedirs(conf["img-dir"])
if not os.path.exists(conf["jar-dir"]):
	os.makedirs(conf["jar-dir"])  # TODO Make this invoke the Maven repo add script instead of just storing jars here
db = APIDatabase(conf["img-dir"], conf["jar-dir"])


class Auth(Resource):
	def get(self):
		"""Login, return a token"""
		parser = RequestParser()
		parser.add_argument("username", help="Must provide username to log in with", type=str, required=True)
		parser.add_argument("password", help="Must provide password to log in with", type=str, required=True)
		args = parser.parse_args()
		if not db.authenticate(args["username"], args["password"]):
			return {"message": "Incorrect username or password"}, 401
		expires = datetime.timedelta(days=20)  # TODO: Change to 1 hour
		atoken = create_access_token(args["username"], expires_delta=expires)
		rtoken = create_refresh_token(args["username"], expires_delta=expires)
		return {
				"message": "Logged in as {}".format(args["username"]),
				"access_token": atoken,
				"refresh_token": rtoken
			}, 200

	def post(self):
		"""Register new user"""
		parser = RequestParser()
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
		return {"message": "Successfully registered as user {}".format(username)}, 201

	def delete(self):
		"""Delete user, requires password as confirmation"""
		parser = RequestParser()
		parser.add_argument("username", help="Must provide username to log in with", required=True, type=str)
		parser.add_argument("password", help="Must provide password to log in with", required=True, type=str)
		args = parser.parse_args()
		if db.authenticate(args["username"], args["password"]):
			db.deleteUser(args["username"])
			return {"message": "Successfully deleted user {}".format(args["username"])}, 200
		else:
			return {"message": "Incorrect username or password"}, 401


class APIList(Resource):

	@jwt_required
	def post(self):
		"""Create or update API data"""
		parser = RequestParser()
		parser.add_argument("action", help="Must provide an action to perform: create, update", required=True, type=str)
		parser.add_argument("info", help="Provide API information as a JSON object", required=True, type=dict)
		args = parser.parse_args()
		action = args["action"]

		if action == "create":
				required = ("name", "contact", "description")
				if all(key in args["info"] for key in required):
					info = args["info"]
					apiID = db.createAPI(get_jwt_identity(), info["name"], info["contact"], info["description"])
					if apiID != "error":
						return {"message": "Created API '{}'".format(info["name"]), "id": apiID}, 201
					else:
						return {"message": "Failed to create API, this error isn't supposed to happen!"}, 400
				else:
					return {"message": "Failed to create API, not enough arguments (name, contact, description) provided"}, 400

		elif action == "update":
			parser.add_argument("id", help="Must provide ID of API to update", required=True, type=str)
			args = parser.parse_args()
			apiID = args["id"]
			if len(args["info"]) == 0:
				return {"message": "Didn't include any data to update"}, 400

			stat, message = db.updateAPI(get_jwt_identity(), apiID, **args["info"])
			db.exportToJSON(conf["json-output"])
			return {"message": message, "id": apiID}, 200 if stat else 400

	@jwt_required
	def delete(self):
		parser = RequestParser()
		parser.add_argument("id", help="Provide ID of API to delete", required=True, type=str)
		apiID = parser.parse_args()["id"]
		if db.deleteAPI(get_jwt_identity(), apiID):
			db.exportToJSON(conf["json-output"])
			return {"message": "Successfully deleted API", "id": apiID}, 200
		else:
			return {"message": "Failed to delete API", "id": apiID}, 400

	def get(self):
		"""Get information on an API, using its ID or its artifact+groupID"""
		parser = RequestParser()
		parser.add_argument("id", required=False, type=str)
		parser.add_argument("artifactID", required=False, type=str)
		parser.add_argument("groupID", required=False, type=str)
		args = parser.parse_args()
		if ("id" not in args.keys()) and (("artifactID" not in args.keys()) or ("groupID" not in args.keys())):
			return {"message": "Didn't provide enough info to retrieve API; either provide an ID or use a "
											"group/artifact combination"}, 400

		res = None
		if args["id"] is not None:
			res = db.getAPIInfo(apiID=args["id"])
		elif args["groupID"] is not None and args["artifactID"] is not None:
			res = db.getAPIInfo(groupID=args["groupID"], artifactID=args["artifactID"])

		if res is None:
			return {"message": "Failed to find API", "id": args["id"]}, 400
		return res


# Run Flask stuff
api.add_resource(Auth, "/api/auth")
api.add_resource(APIList, "/api/list")
if __name__ == "__main__":
	app.run(port="5000")
