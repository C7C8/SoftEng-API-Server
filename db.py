import base64
import html
import json
import os
import re
import time
import uuid

import boto3
import magic
from bcrypt import hashpw, gensalt, checkpw

from maven import store_jar_in_maven_repo


class APIDatabase:
	def __init__(self, img_dir, jar_dir, table, region, bucket_name, access_key, secret_key):
		self.img_dir = img_dir
		self.jar_dir = jar_dir
		self.bucket = boto3.resource("s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key).Bucket(bucket_name)
		self.dynamo = boto3.resource("dynamodb", aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region).Table(table)

	def get_user(self, username):
		"""Get a user's entry, or None if they don't exist"""
		try:
			ret = self.dynamo.get_item(Key={"username": username})
			if "Item" not in ret.keys():
				return None
			return ret["Item"]
		except Exception:
			return None

	def register_user(self, username, password):
		"""Add a user to the database, if they don't already exist."""
		if self.get_user(username) is not None:
			return False

		# TODO Better error handling?
		self.dynamo.put_item(
			Item={
				"username": username,
				"password": hashpw(password, gensalt()),
				"admin": 0,
				"locked": 0,
				"last_login": int(time.time()),
				"registration": int(time.time()),
				"active": 1,
				"apis": []
			}
		)
		return True

	def delete_user(self, username):
		"""Delete a user from the database"""
		user = self.get_user(username)
		if user is None:
			return
		user["username"] = "DELETED_" + user["username"]
		user["active"] = 0
		for api in user["apis"]:
			api["display"] = 0

		self.dynamo.delete_item(Key={"username": username})
		self.dynamo.put_item(Item=user)

	def change_passwd(self, username, password):
		"""Change a user's password"""
		self.dynamo.update_item(
			Key={
				"username": username
			},
			UpdateExpression="SET password = :password",
			ExpressionAttributeValues={
				":password": hashpw(password, gensalt())
			}
		)

	def change_username(self, username, new_username):
		"""Change a username"""
		self.dynamo.update_item(
			Key={
				"username": username
			},
			UpdateExpression="SET username = :username",
			ExpressionAttributeValues={
				":username": new_username
			}
		)

	def set_admin(self, username, admin):
		"""Set whether a user is an admin or not"""
		self.dynamo.update_item(
			Key={
				"username": username
			},
			UpdateExpression="SET admin = :admin",
			ExpressionAttributeValues={
				":admin": admin
			}
		)

	def authenticate(self, username, password):
		"""Authenticate username/password combo, returns tuple of booleans (one for auth, one for admin, one for locked"""
		user = self.get_user(username)
		if user is None or not bool(user["active"]):
			return False, False, False
		auth = checkpw(password, user["password"])
		if auth:
			# Update last login time
			self.dynamo.update_item(
				Key={
					"username": username
				},
				UpdateExpression="SET last_login = :time",
				ExpressionAttributeValues={
					":time": int(time.time())
				}
			)
		else:
			return False, False, False

		return auth, bool(user["admin"]), bool(user["locked"])

	def set_user_lock(self, username, locked):
		self.dynamo.update_item(
			Key={
				"username": username
			},
			UpdateExpression="SET locked = :locked",
			ExpressionAttributeValues={
				":locked": locked
			}
		)

	def create_api(self, username, name, contact, description, term, year, team):
		"""Create base API entry, returns API ID on success"""
		if not self.__validate_args(contact=contact, term=term, year=year, team=team):
			return False, "Bad arguments"

			# Calculate artifact ID and group ID
		artifactID = str().join(c for c in name if c.isalnum())
		groupID = "edu.wpi.cs3733." + term.lower() + str(year)[2:] + ".team" + team.upper()

		# Escape anything HTML-y
		name = html.escape(name)
		description = html.escape(description)
		contact = html.escape(contact)

		# Create base entry
		apiID = str(uuid.uuid4())
		api = {
			"id": apiID,
			"name": name,
			"contact": contact,
			"artifactID": artifactID,
			"groupID": groupID,
			"description": description if len(description) > 0 else "*No description*",
			"term": term,
			"year": year,
			"team": team,
			"size": 0,
			"version": "0.0.0",
			"lastupdate": int(time.time()),
			"display": 1,
			"versions": []
		}

		# TODO Enforce group+artifact uniqueness
		self.dynamo.update_item(
			Key={
				"username": username
			},
			UpdateExpression="SET apis = list_append(apis, :api)",
			ExpressionAttributeValues={
				":api": [api],
			}
		)

		return True, apiID

	def update_api(self, username, api_id, **kwargs):
		"""Update an API entry... anything about it. Returns whether operation succeeded, false+msg if it didn't"""

		# VERIFICATION
		# Verify ownership of API (but skip if user is admin)
		current_user = self.get_user(username)
		if current_user is None:
			return False, "Could not find user issuing update"
		if not bool(current_user["admin"]) and len(list(filter(lambda api: api_id == api["id"], current_user["apis"]))) == 0:
			return False, "Couldn't verify user ownership of API"
		else:
			# The user is an admin, we have to search through everyone's APIs to figure out where the API in question is
			_, current_user = self.__get_api_chain_by_id(api_id)
		current_api = list(filter(lambda api: api_id == api["id"], current_user["apis"]))[0]
		current_api_index = current_user["apis"].index(current_api)

		# Since these values are basically passed in RAW into the db, it's critical to allow only select keywords
		allowed = ("name", "version", "contact", "term", "year", "team", "description", "image", "jar")
		if not all(arg in allowed for arg in kwargs.keys()):
			return False, "Illegal API change argument"
		if not self.__validate_args(**kwargs):
			return False, "Arguments failed validity check"

		# UPDATES

		# Slightly hacky: The arguments in the args dict are the same as the column names in the database API table...
		# OH YEAH! Just pass those things in directly into dynamo
		for key, value in kwargs.items():
			if key == "version" or key == "image" or key == "jar":
				continue
			if key == "description" or key == "name" or key == "contact":
				kwargs[key] = html.escape(value)
			self.dynamo.update_item(
				Key={"username": current_user["username"]},
				UpdateExpression="SET apis[{}].#prop = :val".format(current_api_index),  # KILL ME. Please.
				ExpressionAttributeNames={"#prop": key},
				ExpressionAttributeValues={":val": value}
			)

		# Image processing: decode b64-encoded images, store them in img/directory for now, using API ID
		mime = magic.Magic(mime=True)
		if "image" in kwargs.keys():
			data = base64.standard_b64decode(kwargs["image"])
			mtype = mime.from_buffer(data)
			if mtype.find("image/") != -1:

				# If the DB already has a file listed for this API, delete it
				# S3 would allow overwrites, but not if the filename isn't identical (e.g. *.jpg->*.png)
				filename = None if "image_url" not in current_api.keys() else current_api["image_url"]
				if filename is not None:
					# Okay wtf Amazon, what is WITH this delete syntax?
					self.bucket.delete_objects(Delete={'Objects': [{"Key": filename}]})

				filename = os.path.join(self.img_dir, api_id + "." + mtype[mtype.find("/") + 1:])
				self.dynamo.update_item(
					Key={"username": current_user["username"]},
					UpdateExpression="SET apis[{}].image_url = :img".format(current_api_index),
					ExpressionAttributeValues={":img": filename}
				)
				self.bucket.put_object(Key=filename, Body=data)
			else:
				print("Received image file for API " + api_id + ", but it wasn't an image!")

			# Jar processing: decode b64-encoded jar files, store them in work. Make sure that an appropriate version string
			# is provided, otherwise we can't add it to the repo.
		if "jar" in kwargs.keys() and "version" in kwargs.keys():
			data = base64.standard_b64decode(kwargs["jar"])
			file_type = mime.from_buffer(data)
			if file_type.find("application/zip") == -1 and file_type.find('application/java-archive') == -1:
				return False, "Received file for API but it wasn't a jar file"

			# Update version, size, timestamp
			version_string = re.search("\d+\.\d+\.\d+", kwargs["version"]).group(0)  # Safe because we already validated it
			self.dynamo.update_item(
				Key={"username": current_user["username"]},
				UpdateExpression="SET apis[{}].version = :version".format(current_api_index),
				ExpressionAttributeValues={":version": version_string}
			)
			self.dynamo.update_item(
				Key={"username": current_user["username"]},
				UpdateExpression="SET apis[{}].size= :size".format(current_api_index),
				ExpressionAttributeValues={":size": int(len(data)/1000000)}
			)
			self.dynamo.update_item(
				Key={"username": current_user["username"]},
				UpdateExpression="SET apis[{}].lastupdate = :time".format(current_api_index),
				ExpressionAttributeValues={":time": int(time.time())}
			)

			# Add new entry in version table. TODO Enforce version validity!
			self.dynamo.update_item(
				Key={"username": current_user["username"]},
				UpdateExpression="SET apis[{}].versions= list_append(apis[{}].versions, :version)".format(current_api_index, current_api_index),
				ExpressionAttributeValues={
					":version": [{
						"vnumber": version_string,
						"info": kwargs["version"].replace(version_string, "").lstrip()
					}]
				}
			)

			store_jar_in_maven_repo(base_dir=self.jar_dir,
									group=current_api["groupID"],
									artifact=current_api["artifactID"],
									version=version_string,
									bucket=self.bucket,
									file=base64.standard_b64decode(kwargs["jar"]))

			# Jars must be accompanied by versions; if we have one but not the other, throw an error
		elif ("jar" in kwargs.keys() and "version" not in kwargs.keys()) or ("version" in kwargs.keys() and "jar" not in kwargs.keys()):
			return False, "Jar files must be accompanied by versions" if "jar" in kwargs.keys() else "Empty versions disallowed"
		return True, "Updated API"

	def delete_api(self, username, api_id):
		"""Delete an API and its associated image. Jar files are left intact since others may rely on them."""
		current_user = self.get_user(username)
		if current_user is None:
			return False
		if len(list(filter(lambda api: api_id == api["id"], current_user["apis"]))) == 0:
			if current_user["admin"]:
				_, current_user = self.__get_api_chain_by_id(api_id)
			else:
				return False
		current_api = list(filter(lambda api: api_id == api["id"], current_user["apis"]))[0]
		current_api_index = current_user["apis"].index(current_api)
		self.dynamo.update_item(
			Key={"username": current_user["username"]},
			UpdateExpression="SET apis[{}].display = :n".format(current_api_index),
			ExpressionAttributeValues={":n": 0}
		)
		return True

	def get_api_info(self, api_id=None, api=None, user=None):
		"""Get an API info dict using apiID or a groupID+artifactID combination"""
		# Get basic API info
		if api is None or user is None:
			api, user = self.__get_api_chain_by_id(api_id)

		# Fill out base API info data structure
		ret = {
			"id": api_id if api_id is not None else api["id"],
			"name": api["name"],
			"version": api["version"],
			"size": float(api["size"]),
			"contact": api["contact"],
			"gradle": "[group: '{}', name: '{}', version:'{}']".format(api["groupID"], api["artifactID"], api["version"]),
			"description": api["description"],
			"image": "" if "image_url" not in api.keys() else api["image_url"],
			"updated": int(api["lastupdate"]) * 1000,
			"term": api["term"],
			"year": api["year"],
			"team": api["team"],
			"creator": user["username"] if user is None else user,
			"history": ["{}: {}".format(version["vnumber"], version["info"]) for version in api["versions"]]
		}

		return ret

	def get_user_list(self):
		"""Get a list of users and whether they're admin or not, as a list of tuples"""
		users = self.dynamo.scan()["Items"]
		return [
			{
				"username": user["username"],
				"admin": bool(user["admin"]),
				"registered": int(user["registration"] * 1000),
				"last_login": int(user["last_login"] * 1000),
				"locked": bool(user["locked"])
			} for user in users if user["active"] == 1]

	def export_db_to_json(self, filename):
		"""Export the API db to a certain format JSON file"""
		ret = {
			"count": 0,
			"totalCount": 0,
			"size": 0,
			"totalSize": 0,
			"classes": []
		}

		# Collect aggregate stats
		users = self.dynamo.scan()["Items"]
		apis = []
		for user in users:
			for api in user["apis"]:
				ret["totalCount"] += 1
				ret["totalSize"] += float(api["size"])
				if api["display"] == 1:
					ret["count"] += 1
					ret["size"] += float(api["size"])
					apis.append(api)
				api["creator"] = user["username"]
				api["year"] = int(api["year"])
		apis = sorted(apis, key=(lambda api: str(api["year"] - 1 if api["term"] > 'B' else api["year"]) + api["term"]), reverse=True)

		# Assemble final structure
		currTerm = None
		currYear = None
		index = -1
		for api in apis:
			apiInfo = self.get_api_info(api=api, user=api["creator"])
			if (apiInfo["term"] != currTerm) or (apiInfo["year"] != currYear):
				currTerm = apiInfo["term"]
				currYear = apiInfo["year"]
				index += 1
				ret["classes"].append({
					"term": currTerm,
					"year": currYear,
					"apis": []
				})
			ret["classes"][index]["apis"].append(apiInfo)

		self.bucket.put_object(Key=filename, Body=json.dumps(ret))

	def __get_api_chain_by_id(self, api_id):
		"""Get an API chain by ID -- that means the API object and the user that owns it"""
		users = self.dynamo.scan()["Items"]
		users = list(filter(lambda user: len(list(filter(lambda api: api_id == api["id"], user["apis"]))) > 0, users))
		if len(users) == 0:
			return False, "Could not find API"
		current_user = users[0]
		current_api = list(filter(lambda api: api_id == api["id"], current_user["apis"]))[0]
		return current_api, current_user

	@staticmethod
	def __validate_args(**kwargs):
		"""Validates select API info args. Returns true if they check out, false otherwise"""
		if "contact" in kwargs.keys():
			# Simple email validation -- make sure there's exactly one @ with text before and after it
			if re.search("^[^@]+@[^@]+$", kwargs["contact"]) is None:
				return False
		if "term" in kwargs.keys():
			if kwargs["term"] not in ["A", "B", "C", "D"]:
				return False
		if "year" in kwargs.keys():
			if re.search("^\d{4}$", str(kwargs["year"])) is None:
				return False
		if "team" in kwargs.keys():
			if re.search("^[A-Z]$", kwargs["team"]) is None or len(kwargs["team"]) > 1:
				return False
		if "version" in kwargs.keys():
			if re.search("^\d+\.\d+\.\d+", kwargs["version"]) is None:
				return False
		if "description" in kwargs.keys():  # Anti-XSS, somehow showdown.js lets this get by in [](link) format
			if re.search("\(.*javascript:.*\)", kwargs["description"]) is not None:
				return False
		return True
