import os
import datetime
from json import loads
from flask import Flask, Blueprint
from flask_restplus import Api, Namespace, Resource, reqparse
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, JWTManager

from apiDB import APIDatabase


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

# Set up flask
app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = conf["jwt-key"]
jwt = JWTManager(app)
apiV1 = Blueprint('api', __name__)
api = Api(apiV1, version="1.0.0", title="CS 3733 API API", description="Not a typo")
jwt._set_error_handler_callbacks(api)  # plz stop returning 500 Server Error
ns = api.namespace("api", description="API list functionality")

db = APIDatabase(conf["img-dir"], conf["jar-dir"])

if not os.path.exists(conf["img-dir"]):
	os.makedirs(conf["img-dir"])
if not os.path.exists(conf["jar-dir"]):
	os.makedirs(conf["jar-dir"])  # TODO Make this invoke the Maven repo add script instead of just storing jars here


@ns.route("/auth")
class Auth(Resource):
	def get(self):
		"""Login, return a token"""
		parser = reqparse.RequestParser()
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
		parser = reqparse.RequestParser()
		parser.add_argument("username", help="Must provide username to register", required=True, type=str)
		parser.add_argument("password", help="Must provide password to set for new user", required=True, type=str)

		args = parser.parse_args()
		if not db.registerUser(args["username"], args["password"]):
			return {"message": "Registration failed"}, 403
		return {"message": "Successfully registered as user {}".format(args["username"])}, 201

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


@ns.route("/list")
class APIList(Resource):
	@jwt_required
	def post(self):
		"""Create or update API data"""
		if not db.checkUserExists(get_jwt_identity()):
			return {"message": "User does not exist", "username": get_jwt_identity()}, 401

		parser = reqparse.RequestParser()
		parser.add_argument("action", help="Must provide an action to perform: create, update", required=True, type=str)
		parser.add_argument("info", help="Provide API information as a JSON object", required=True, type=dict)
		args = parser.parse_args()
		action = args["action"]

		if action == "create":
			required = ("name", "contact", "description", "term", "year", "team")
			if all(key in args["info"] for key in required):
				info = args["info"]
				apiID = db.createAPI(get_jwt_identity(), info["name"], info["contact"], info["description"], info["term"],
																									info["year"], info["team"])
				if apiID != "error":
					return {"message": "Created API '{}'".format(info["name"]), "id": apiID}, 201
				else:
					return {"message": "Failed to create API, this error isn't supposed to happen!"}, 400
			else:
				return {"message": "Failed to create API, not enough arguments (name, contact, description, term, year, " 
												"team) provided"}, 400

		elif action == "update":
			parser.add_argument("id", help="Provide API's ID", required=False, type=str)
			parser.add_argument("groupID", help="Provide API's group ID", required=False, type=str)
			parser.add_argument("artifactID", help="Provide API's artifact ID", required=False, type=str)
			args = parser.parse_args()
			if (args["id"] is None) and ((args["artifactID"] is None) or (args["groupID"] is None)):
				return {"message": "Didn't provide enough info to find API; either provide an ID or use a "
												"group/artifact combination"}, 400
			args = parser.parse_args()
			apiID = args["id"] if args["id"] is not None else db.getAPIId(args["groupID"], args["artifactID"])
			if apiID is None:
				return {"message": "Failed to find API"}, 400

			if len(args["info"]) == 0:
				return {"message": "Didn't include any data to update"}, 400

			stat, message = db.updateAPI(get_jwt_identity(), apiID, **args["info"])
			db.exportToJSON(conf["json-output"])
			return {"message": message, "id": apiID}, 200 if stat else 400

	@jwt_required
	def delete(self):
		"""Delete an API listing and all associated metadata. Does NOT delete Jar files from the Maven repository"""
		if not db.checkUserExists(get_jwt_identity()):
			return {"message": "User does not exist", "username": get_jwt_identity()}, 401

		parser = reqparse.RequestParser()
		parser.add_argument("id", help="Provide API's ID", required=False, type=str)
		parser.add_argument("groupID", help="Provide API's group ID", required=False, type=str)
		parser.add_argument("artifactID", help="Provide API's artifact ID", required=False, type=str)
		args = parser.parse_args()
		if (args["id"] is None) and ((args["artifactID"] is None) or (args["groupID"] is None)):
			return {"message": "Didn't provide enough info to find API; either provide an ID or use a "
											"group/artifact combination"}, 400

		apiID = args["id"] if args["id"] is not None else db.getAPIId(args["groupID"], args["artifactID"])

		if apiID is not None and db.deleteAPI(get_jwt_identity(), apiID):
			db.exportToJSON(conf["json-output"])
			return {"message": "Successfully deleted API", "id": apiID}, 200
		else:
			return {"message": "Failed to delete API", "id": apiID}, 400

	def get(self):
		"""Get information on an API, using its ID or its artifact+groupID"""
		parser = reqparse.RequestParser()
		parser.add_argument("id", required=False, type=str)
		parser.add_argument("artifactID", required=False, type=str)
		parser.add_argument("groupID", required=False, type=str)
		args = parser.parse_args()
		if (args["id"] is None) and ((args["artifactID"] is None) or (args["groupID"] is None)):
			return {"message": "Didn't provide enough info to find API; either provide an ID or use a "
											"group/artifact combination"}, 400

		# Python won't let me do C-style assignments in if statements, so yeah, there's duped code here. Deal with it.
		apiID = args["id"] if args["id"] is not None else db.getAPIId(args["groupID"], args["artifactID"])
		if apiID is None:
			return {"message": "Failed to find API", "id": args["id"]}, 400
		res = db.getAPIInfo(apiID)
		if res is None:
			return {"message": "Failed to find API", "id": args["id"]}, 400
		return res


app.register_blueprint(apiV1)
print(app.url_map)
# Run Flask stuff
if __name__ == "__main__":
	app.run(port="5000", debug=True)
