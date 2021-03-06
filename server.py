import datetime
from json import loads

from flask import Flask, Blueprint
from flask_cors import CORS
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, JWTManager
from flask_restplus import Api, Resource, reqparse

from db import APIDatabase

# Load configuration
conf = {
	"server": {
		"server-port": 5000,
		"jwt-key": "DEFAULT_SECRET_KEY",
		"img-dir": "img",
		"jar-dir": "maven",
		"json-output": "list.json"
	},
	"aws": {
		"region": "us-east-1",
		"access-key": "",
		"secret-key": "",
		"dynamo": {
			"table": "apisite"
		},
		"s3": {
			"bucket": "apisite.crmyers.dev"
		}
	}
}
try:
	with open("conf.json", "r") as file:
		conf = loads(file.read())
except FileNotFoundError:
	print("Couldn't load server conf 'conf.json', using default settings! This is extremely dangerous!")
server_conf = conf["server"]
aws_conf = conf["aws"]

# Set up flask
app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = conf["server"]["jwt-key"]
CORS(app)
jwt = JWTManager(app)
apiV1 = Blueprint('api', __name__)
api = Api(apiV1, version="1.0.0", title="CS 3733 API API", description="Not a typo; serves up info on Java APIs created"
																	   " as part of CS 3733 Software Engineering")
app.register_blueprint(apiV1)
jwt._set_error_handler_callbacks(api)  # plz stop returning 500 Server Error
ns = api.namespace("", description="API list functionality")

db = APIDatabase(server_conf["img-dir"], server_conf["jar-dir"], aws_conf["dynamo"]["table"], aws_conf["region"],
				 aws_conf["s3"]["bucket"], aws_conf["access-key"], aws_conf["secret-key"])


def response(success, message, descriptor=None, payload=None):
	"""Helper to generate standard format API responses"""
	if descriptor is None:
		return {"status": "success" if success else "error", "message": message}
	else:
		return {"status": "success" if success else "error", "message": message, descriptor: payload}


# Helper wrapper to make admin privilege checking smoother
def admin_required(func):
	def wrapper(self):
		print("Checking admin privileges on " + get_jwt_identity())
		if not bool(db.get_user(get_jwt_identity())["admin"]):
			return response(False, "Admin access not authorized"), 403
		return func(self)

	return wrapper


# API endpoints

@ns.route("/auth/register")
class Register(Resource):
	def post(self):
		"""Register new user"""
		parser = reqparse.RequestParser()
		parser.add_argument("username", required=True, type=str)
		parser.add_argument("password", required=True, type=str)

		args = parser.parse_args()
		if not db.register_user(args["username"], args["password"]):
			return response(False, "Registration failed"), 403
		return response(True, "Successfully registered as user {}".format(args["username"])), 201

	def delete(self):
		"""Delete user, requires password as confirmation"""
		parser = reqparse.RequestParser()
		parser.add_argument("username", required=True, type=str)
		parser.add_argument("password", required=True, type=str)
		args = parser.parse_args()
		if db.authenticate(args["username"], args["password"]):
			db.delete_user(args["username"])
			db.export_db_to_json(server_conf["json-output"])
			return response(True, "Successfully deleted user {}".format(args["username"])), 200
		else:
			return response(False, "Invalid credentials"), 401


@ns.route("/auth/login")
class Login(Resource):
	def post(self):
		"""Login, return a token"""
		parser = reqparse.RequestParser()
		parser.add_argument("username", required=True, type=str)
		parser.add_argument("password", required=True, type=str)

		args = parser.parse_args()
		auth, admin, locked = db.authenticate(args["username"], args["password"])
		if not auth:
			return response(False, "Invalid credentials"), 401
		if locked:
			return response(False, "Account locked, please contact site administrator!")
		# expires = datetime.timedelta(hours=1)
		token = create_access_token(args["username"], expires_delta=False)
		return {
				   "status": "success",
				   "message": "Logged in as {}".format(args["username"]),
				   "admin": admin,
				   "access_token": token,
			   }, 200


@ns.route("/list")
class List(Resource):
	@jwt_required
	def post(self):
		"""Create or update API data"""
		if db.get_user(get_jwt_identity()) is None:
			return response(False, "User does not exist", "username", get_jwt_identity()), 401

		parser = reqparse.RequestParser()
		parser.add_argument("action", help="Action (create, update)", required=True, type=str)
		parser.add_argument("info", help="Info structure", required=True, type=dict)
		args = parser.parse_args()
		action = args["action"]

		if action == "create":
			required = ("name", "description", "term", "year", "team")
			if all(key in args["info"] for key in required):
				info = args["info"]
				res, apiID = db.create_api(get_jwt_identity(), info["name"], info["contact"], info["description"],
										   info["term"],
										   info["year"], info["team"])
				if res:
					db.export_db_to_json(server_conf["json-output"])
					return response(True, "Created API '{}'".format(info["name"]), "id", apiID), 201
				else:
					return response(False, "Failed to create API '{}': {}".format(info["name"], apiID)), 400
			else:
				return response(False,
								"Failed to create API< not enough arguments (name, contact, description, term, year, team)"), 400

		elif action == "update":
			parser.add_argument("id", help="API ID", required=True, type=str)
			args = parser.parse_args()

			if len(args["info"].keys()) == 0:
				return response(False, "Didn't include any data to update"), 400

			stat, message = db.update_api(get_jwt_identity(), args["id"], **args["info"])
			db.export_db_to_json(server_conf["json-output"])
			return response(stat, message, "id", args["id"]), 200 if stat else 400

	@jwt_required
	def delete(self):
		"""Delete an API listing and all associated metadata. Does NOT delete Jar files from the Maven repository"""
		if db.get_user(get_jwt_identity()) is None:
			return {"message": "User does not exist", "username": get_jwt_identity()}, 401

		parser = reqparse.RequestParser()
		parser.add_argument("id", help="API ID", required=True, type=str)
		args = parser.parse_args()

		if db.delete_api(get_jwt_identity(), args["id"]):
			db.export_db_to_json(server_conf["json-output"])
			return response(True, "Successfully deleted API", "id", args["id"]), 200
		else:
			return response(False, "Failed to delete API", "id", args["id"]), 400

	def get(self):
		"""Get information on an API, using its ID or its artifact+groupID"""
		parser = reqparse.RequestParser()
		parser.add_argument("id", required=True, type=str)
		args = parser.parse_args()

		# Python won't let me do C-style assignments in if statements, so yeah, there's duped code here. Deal with it.
		res = db.get_api_info(args["id"])
		if res is None:
			return response(False, "Failed to find API", "id", args["id"]), 400
		return res


@ns.route("/admin")
class Admin(Resource):
	"""Endpoints for the admin access feature"""

	@jwt_required
	@admin_required
	def get(self):
		"""Get list of users"""
		users = db.get_user_list()
		return response(True, "Retrieved {} users".format(len(users)), "users", users), 200

	@jwt_required
	@admin_required
	def post(self):
		"""Modify user"""
		parser = reqparse.RequestParser()
		parser.add_argument("username", required=True, type=str)
		parser.add_argument("new_username", required=False, type=str)
		parser.add_argument("new_password", required=False, type=str)
		parser.add_argument("set_admin", required=False, type=bool)
		parser.add_argument("lock", required=False, type=bool)
		args = parser.parse_args()

		if db.get_user(args["username"]) is None:
			return response(False, "User does not exist"), 400

		# Set / remove admin for users, but don't allow users to de-admin themselves!
		if args["set_admin"] is not None:
			if args["username"] == get_jwt_identity():
				return response(False,
								"For safety you can't de-admin yourself, use another account or get someone else to do it"), 400
			db.set_admin(args["username"], args["set_admin"])

		# Change password
		if args["new_password"] is not None:
			db.change_passwd(args["username"], args["new_password"])

		# Username changes (why would anyone WANT this?)
		if args["new_username"] is not None:
			db.change_username(args["username"], args["new_username"])

		# Lock user from accessing their account
		if args["lock"] is not None:
			db.set_user_lock(args["username"], args["lock"])

		return response(True, "User '{}' modified".format(args["username"]))

	@jwt_required
	@admin_required
	def delete(self):
		"""Delete a user"""
		parser = reqparse.RequestParser()
		parser.add_argument("username", required=True, type=str)
		username = parser.parse_args()["username"]
		if db.get_user(username) is None:
			return response(False, "User does not exist"), 400
		db.delete_user(username)
		return response(True, "User deleted"), 200


# Run Flask development server
if __name__ == "__main__":
	app.run()
