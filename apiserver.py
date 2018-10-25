import os
import datetime
from json import loads

from flask import Flask, Blueprint, make_response
from flask_restplus import Api, Resource, reqparse, fields
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, JWTManager

from apiDB import APIDatabase


# Load configuration
conf = {
	"server-port": 5000,
	"jwt-key": "DEFAULT PRIVATE KEY",
	"img-dir": "img",
	"jar-dir": "jar",
	"json-output": "apilist.json",
	"db-host": "localhost",
	"db-port": 3306,
	"db-user": "list-api-service",
	"db-password": "pass",
	"db-schema": "apilist"
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
api = Api(apiV1, version="1.0.0", title="CS 3733 API API", description="Not a typo; serves up info on Java APIs created"
																		" as part of CS 3733 Software Engineering")
jwt._set_error_handler_callbacks(api)  # plz stop returning 500 Server Error
ns = api.namespace("api", description="API list functionality")

db = APIDatabase(conf["db-host"], conf["db-port"], conf["db-user"], conf["db-password"], conf["db-schema"],
				 conf["img-dir"], conf["jar-dir"])

if not os.path.exists(conf["img-dir"]):
	os.makedirs(conf["img-dir"])
if not os.path.exists(conf["jar-dir"]):
	os.makedirs(conf["jar-dir"])

# API endpoints

@ns.route("/auth/register")
class Register(Resource):
	def post(self):
		"""Register new user"""
		parser = reqparse.RequestParser()
		parser.add_argument("username", help="Username", required=True, type=str)
		parser.add_argument("password", help="Password", required=True, type=str)

		args = parser.parse_args()
		if not db.register_user(args["username"], args["password"]):
			return {"status": "error", "message": "Registration failed"}, 403
		return {"status": "success", "message": "Successfully registered as user {}".format(args["username"])}, 201

	def delete(self):
		"""Delete user, requires password as confirmation"""
		parser = reqparse.RequestParser()
		parser.add_argument("username", help="Must provide username to log in with", required=True, type=str)
		parser.add_argument("password", help="Must provide password to log in with", required=True, type=str)
		args = parser.parse_args()
		if db.authenticate(args["username"], args["password"]):
			db.delete_user(args["username"])
			return {"status": "success", "message": "Successfully deleted user {}".format(args["username"])}, 200
		else:
			return {"status": "error", "message": "Invalid credentials"}, 401


@ns.route("/auth/login")
class Login(Resource):
	def post(self):
		"""Login, return a token"""
		parser = reqparse.RequestParser()
		parser.add_argument("username", help="Username", required=True, type=str)
		parser.add_argument("password", help="Password", required=True, type=str)

		args = parser.parse_args()
		if not db.authenticate(args["username"], args["password"]):
			return {"status": "error", "message": "Invalid credentials"}, 401
		expires = datetime.timedelta(hours=1)
		atoken = create_access_token(args["username"], expires_delta=expires)
		return {
				   "status": "success",
				   "message": "Logged in as {}".format(args["username"]),
				   "access_token": atoken,
			   }, 200


@ns.route("/list")
class APIList(Resource):
	@jwt_required
	def post(self):
		"""Create or update API data"""
		if not db.check_user_exists(get_jwt_identity()):
			return {"status": "error", "message": "User does not exist", "username": get_jwt_identity()}, 401

		parser = reqparse.RequestParser()
		parser.add_argument("action", help="Action (create, update)", required=True, type=str)
		parser.add_argument("info", help="Info structure", required=True, type=dict)
		args = parser.parse_args()
		action = args["action"]

		if action == "create":
			required = ("name", "description", "term", "year", "team")
			if all(key in args["info"] for key in required):
				info = args["info"]
				res, apiID = db.create_api(get_jwt_identity(), info["name"], info["contact"], info["description"], info["term"],
										   info["year"], info["team"])
				if res:
					db.export_db_to_json(conf["json-output"])
					return {"status": "success", "message": "Created API '{}'".format(info["name"]), "id": apiID}, 201
				else:
					return {"status": "error", "message": "Failed to create API: " + apiID}, 400
			else:
				return {"status": "error", "message": "Failed to create API, not enough arguments (name, contact, description, term, year, " 
												"team) provided"}, 400

		elif action == "update":
			parser.add_argument("id", help="API ID", required=False, type=str)
			parser.add_argument("groupID", help="API group ID", required=False, type=str)
			parser.add_argument("artifactID", help="API artifact ID", required=False, type=str)
			args = parser.parse_args()
			if (args["id"] is None) and ((args["artifactID"] is None) or (args["groupID"] is None)):
				return {"status": "error", "message": "Didn't provide enough info to find API; either provide an ID or use a "
												"group/artifact combination"}, 400

			apiID = args["id"] if args["id"] is not None else db.get_api_id(args["groupID"], args["artifactID"])
			if apiID is None:
				return {"status": "error", "message": "Failed to find API"}, 400

			if len(args["info"]) == 0:
				return {"status": "error", "message": "Didn't include any data to update"}, 400

			stat, message = db.update_api(get_jwt_identity(), apiID, **args["info"])
			db.export_db_to_json(conf["json-output"])
			return {"status": "success" if stat else "error","message": message, "id": apiID}, 200 if stat else 400

	@jwt_required
	def delete(self):
		"""Delete an API listing and all associated metadata. Does NOT delete Jar files from the Maven repository"""
		if not db.check_user_exists(get_jwt_identity()):
			return {"message": "User does not exist", "username": get_jwt_identity()}, 401

		parser = reqparse.RequestParser()
		parser.add_argument("id", help="API ID", required=False, type=str)
		parser.add_argument("groupID", help="API group ID", required=False, type=str)
		parser.add_argument("artifactID", help="API artifact ID", required=False, type=str)
		args = parser.parse_args()

		if (args["id"] is None) and ((args["artifactID"] is None) or (args["groupID"] is None)):
			return {"status": "error", "message": "Didn't provide enough info to find API; either provide an ID or use a "
											"group/artifact combination"}, 400

		apiID = args["id"] if args["id"] is not None else db.get_api_id(args["groupID"], args["artifactID"])

		if apiID is not None and db.delete_api(get_jwt_identity(), apiID):
			db.export_db_to_json(conf["json-output"])
			return {"status": "success", "message": "Successfully deleted API", "id": apiID}, 200
		else:
			return {"status": "error", "message": "Failed to delete API", "id": apiID}, 400

	def get(self):
		"""Get information on an API, using its ID or its artifact+groupID"""
		parser = reqparse.RequestParser()
		parser.add_argument("id", required=False, type=str)
		parser.add_argument("artifactID", required=False, type=str)
		parser.add_argument("groupID", required=False, type=str)
		args = parser.parse_args()
		if (args["id"] is None) and ((args["artifactID"] is None) or (args["groupID"] is None)):
			return {"status": "error", "message": "Didn't provide enough info to find API; either provide an ID or use a "
											"group/artifact combination"}, 400

		# Python won't let me do C-style assignments in if statements, so yeah, there's duped code here. Deal with it.
		apiID = args["id"] if args["id"] is not None else db.get_api_id(args["groupID"], args["artifactID"])
		if apiID is None:
			return {"status": "error", "message": "Failed to find API", "id": args["id"]}, 400
		res = db.get_api_info(apiID)
		if res is None:
			return {"status": "error", "message": "Failed to find API", "id": args["id"]}, 400
		return res


# Run Flask stuff
app.register_blueprint(apiV1)
if __name__ == "__main__":
	app.run(port=conf["server-port"])
