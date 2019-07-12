import base64
import html
import json
import os
import re
import time
import uuid
from distutils.version import StrictVersion

import boto3
import magic
import pymysql
from bcrypt import hashpw, gensalt, checkpw

from maven import store_jar_in_maven_repo


class APIDatabase:
	def __init__(self, host, port, user, password, database, img_dir, jar_dir, bucket_name, access_key, secret_key):
		self.host = host
		self.port = port
		self.user = user
		self.password = password
		self.database = database
		self.img_dir = img_dir
		self.jar_dir = jar_dir
		self.bucket = boto3.resource("s3", aws_access_key_id=access_key, aws_secret_access_key=secret_key).Bucket(bucket_name)

	def connect(self):
		return pymysql.connect(host=self.host,
							   port=self.port,
							   database=self.database,
							   user=self.user,
							   password=self.password).cursor()

	def register_user(self, username, password):
		"""Add a user to the database, if they don't already exist."""
		with self.connect() as cursor:
			if self.check_user_exists(username):
				return False

			sql = "INSERT INTO user (username, password) VALUES(%s, %s)"
			cursor.execute(sql, (username, hashpw(password, gensalt())))
			cursor.connection.commit()
			return True

	def delete_user(self, username):
		"""Delete a user from the database"""
		with self.connect() as cursor:
			cursor.execute("UPDATE api SET creator=NULL, display='N' WHERE creator=%s", username)
			cursor.execute("DELETE FROM user WHERE username=%s", username)
			cursor.connection.commit()

	def change_passwd(self, username, password):
		"""Change a user's password"""
		with self.connect() as cursor:
			sql = "UPDATE user SET password=%s WHERE username=%s"
			cursor.execute(sql, (hashpw(password, gensalt()), username))
			cursor.connection.commit()

	def change_username(self, username, new_username):
		"""Change a username"""
		with self.connect() as cursor:
			cursor.execute("UPDATE user SET username=%s WHERE username=%s", (new_username, username))
			cursor.execute("UPDATE api SET creator=%s WHERE creator=%s", (new_username, username))
			cursor.connection.commit()

	def set_admin(self, username, admin):
		"""Set whether a user is an admin or not"""
		with self.connect() as cursor:
			cursor.execute("UPDATE user SET admin=%s WHERE username=%s", (1 if admin else 0, username))
			cursor.connection.commit()

	def authenticate(self, username, password):
		"""Authenticate username/password combo, returns tuple of booleans (one for auth, one for admin, one for locked"""
		with self.connect() as cursor:
			cursor.execute("SELECT password, admin, locked FROM user WHERE username=%s", username)
			res = cursor.fetchone()
			if res is None:
				return False, False, False

			auth, admin = checkpw(password, res[0]), res[1] > 0

			# Set the user's last login time
			if auth:
				cursor.execute("UPDATE user SET last_login=CURRENT_TIMESTAMP WHERE username=%s", username)
				cursor.connection.commit()

			return auth, admin, res[2]

	def is_admin(self, username):
		with self.connect() as cursor:
			cursor.execute("SELECT admin FROM user WHERE username=%s", username)
			res = cursor.fetchone()
			if res is None:
				return False

			return res[0] > 0

	def set_user_lock(self, username, locked):
		with self.connect() as cursor:
			cursor.execute("UPDATE user SET locked=%s WHERE username=%s", (locked, username))
			cursor.connection.commit()

	def check_user_exists(self, username):
		"""Verify that a user exists; helper function for JWT authentication"""
		with self.connect() as cursor:
			sql = "SELECT * FROM user WHERE username=%s"
			cursor.execute(sql, username)
			return cursor.fetchone() is not None

	def create_api(self, username, name, contact, description, term, year, team):
		"""Create base API entry, returns API ID on success"""
		with self.connect() as cursor:
			if not self.__validate_args(contact=contact, term=term, year=year, team=team):
				return False, "Bad arguments"

			# Calculate artifact ID and group ID
			artifactID = str().join(c for c in name if c.isalnum())
			groupID = "edu.wpi.cs3733." + term.lower() + str(year)[2:] + ".team" + team.upper()

			# Escape anything HTML-y
			name = html.escape(name)
			description = html.escape(description)
			contact = html.escape(contact)

			# Create base entry in master API table
			sql = "INSERT INTO api (id, name, version, contact, description, creator, artifactID, groupID, term, year, team) " \
				"VALUES(%s, %s, '1.0.0', %s, %s, %s, %s, %s, %s, %s, %s)"
			apiID = str(uuid.uuid4())
			try:
				cursor.execute(sql, (apiID, name, contact, description, username, artifactID, groupID, term, year, team))
			except pymysql.IntegrityError:
				return False, "API with that artifact+groupID already exists, try changing your API's name"
			cursor.connection.commit()

			return True, apiID

	def update_api(self, username, api_id, **kwargs):
		"""Update an API entry... anything about it. Returns whether operation succeeded, false+msg if it didn't"""

		with self.connect() as cursor:
			# VERIFICATION
			# Verify ownership of API (but skip if user is admin)
			if not self.is_admin(username):
				cursor.execute("SELECT creator FROM api WHERE id=%s", api_id)
				res = cursor.fetchone()
				if res is None or res[0] != username:
					return False, "Couldn't verify user ownership of API"

			# Since these values are basically passed in RAW into the db, it's critical to allow only select keywords
			allowed = ("name", "version", "contact", "term", "year", "team", "description", "image", "jar")
			if not all(arg in allowed for arg in kwargs.keys()):
				return False, "Illegal API change argument"

			if not self.__validate_args(**kwargs):
				return False, "Arguments failed validity check"

			# UPDATES

			# Slightly hacky: The arguments in the args dict are the same as the column names in the database API table...
			# OH YEAH! Just iterate over every key, substituting in its name for the update, and the corresponding data
			for key in kwargs.keys():
				if key == "version" or key == "image" or key == "jar":
					continue
				if key == "description" or key == "name" or key == "contact":
					kwargs[key] = html.escape(kwargs[key])
				sql = "UPDATE api SET {}=%s WHERE id=%s AND display='Y'".format(key)
				cursor.execute(sql, (kwargs[key], api_id))

			# Image processing: decode b64-encoded images, store them in img/directory for now, using API ID
			mime = magic.Magic(mime=True)
			if "image" in kwargs.keys():
				data = base64.standard_b64decode(kwargs["image"])
				mtype = mime.from_buffer(data)
				if mtype.find("image/") != -1:

					# If the DB already has a file listed for this API, delete it
					# S3 would allow overwrites, but not if the filename isn't identical (e.g. *.jpg->*.png)
					filename = self.__get_image_name(api_id)
					if filename is not None:
						# Okay wtf Amazon, what is WITH this delete syntax?
						self.bucket.delete_objects(Delete={'Objects': [{"Key": filename}]})

					filename = os.path.join(self.img_dir, api_id + "." + mtype[mtype.find("/") + 1:])
					cursor.execute("UPDATE api SET image_url=%s WHERE id=%s", (filename, api_id))
					cursor.connection.commit()
					self.bucket.put_object(Key=filename, Body=data)
				else:
					print("Received image file for API " + api_id + ", but it wasn't an image!")

			# Jar processing: decode b64-encoded jar files, store them in work. Make sure that an appropriate version string
			# is provided, otherwise we can't add it to the repo.
			if "jar" in kwargs.keys() and "version" in kwargs.keys():
				data = base64.standard_b64decode(kwargs["jar"])
				file_type = mime.from_buffer(data)
				if file_type.find("application/zip") == -1 and file_type.find('application/java-archive') == -1:
					cursor.connection.rollback()
					return False, "Received file for API but it wasn't a jar file"

				# Update version, size, timestamp
				sql = "UPDATE api SET version=%s, size=%s, lastupdate=CURRENT_TIMESTAMP() WHERE id=%s"
				version_string = re.search("\d+\.\d+\.\d+", kwargs["version"]).group(0)  # Safe because we already validated it
				cursor.execute(sql, (version_string, len(data) / 1000000, api_id))  # bytes -> mb

				# Add version string to new entry in version table
				sql = "INSERT INTO version(apiId, vnumber, info) VALUES (%s, %s, %s)"
				try:
					cursor.execute(sql, (api_id, version_string, kwargs["version"].replace(version_string, "").lstrip()))
				except pymysql.IntegrityError:
					cursor.connection.rollback()
					return False, "Failed to update API; duplicate version detected"

				sql = "SELECT groupID, artifactID FROM api WHERE id=%s"
				cursor.execute(sql, api_id)
				res = cursor.fetchone()
				store_jar_in_maven_repo(base_dir=self.jar_dir,
										group=res[0],
										artifact=res[1],
										version=version_string,
										bucket=self.bucket,
										file=base64.standard_b64decode(kwargs["jar"]))

			# Jars must be accompanied by versions; if we have one but not the other, throw an error
			elif ("jar" in kwargs.keys() and "version" not in kwargs.keys())\
					or ("version" in kwargs.keys() and "jar" not in kwargs.keys()):
				cursor.connection.rollback()
				return False, "Jar files must be accompanied by versions" if "jar" in kwargs.keys() else "Empty versions disallowed"

			cursor.connection.commit()
		return True, "Updated API"

	def delete_api(self, username, api_id):
		"""Delete an API and its associated image. Jar files are left intact since others may rely on them."""

		with self.connect() as cursor:
			# Verify the API actually exists and that this user owns it
			# (unless they're admin, in which case they can do whatever)
			cursor.execute("SELECT creator FROM api WHERE id=%s AND display='Y'", api_id)
			res = cursor.fetchone()
			if res is None or (res[0] != username and not self.is_admin(username)):
				return False

			cursor.execute("UPDATE api SET display='N' WHERE id=%s", api_id)
			cursor.connection.commit()
			return True

	def get_api_id(self, group_id, artifact_id):
		"""Get an API's ID, required for database operations involving APIs"""
		with self.connect() as cursor:
			sql = "SELECT id FROM api WHERE groupID=%s AND artifactID=%s AND display='Y'"
			cursor.execute(sql, (group_id, artifact_id))
			res = cursor.fetchone()
			if res is None:
				return None
			return res[0]

	def get_api_info(self, api_id):
		"""Get an API info dict using apiID or a groupID+artifactID combination"""
		# Get basic API info
		with self.connect() as cursor:
			sql = "SELECT name, contact, artifactID, groupID, version, description, lastupdate, id, creator, size, " \
				"term, year, team FROM api WHERE id=%s AND display='Y'"
			cursor.execute(sql, api_id)
			res = cursor.fetchone()
			if res is None:
				return None

			# Fill out base API info data structure
			ret = {
				"id": api_id,
				"name": res[0],
				"version": res[4],
				"size": res[9],
				"contact": res[1],
				"gradle": "[group: '{}', name: '{}', version:'{}']".format(res[3], res[2], res[4]),
				"description": res[5],
				"image": self.__get_image_name(api_id),
				"updated": time.mktime(res[6].timetuple()) * 1000,
				"term": res[10],
				"year": res[11],
				"team": res[12],
				"creator": res[8]
			}

			# Get version history
			sql = "SELECT vnumber, info FROM version WHERE apiID=%s"
			cursor.execute(sql, api_id)
			res = cursor.fetchall()
			vlist = []
			if res is not None and len(res) > 0:
				for version in sorted(res, key=lambda x: StrictVersion(x[0])):
					vlist.append(version[0] + ": " + version[1])

			ret["history"] = vlist
			return ret

	def get_user_list(self):
		"""Get a list of users and whether they're admin or not, as a list of tuples"""
		with self.connect() as cursor:
			cursor.execute("SELECT username, admin, registration, last_login, locked FROM user")
			results = cursor.fetchall()
			ret = []
			for res in results:
				ret.append({
					"username": res[0],
					"admin": res[1] > 0,
					"registered": time.mktime(res[2].timetuple()) * 1000,
					"last_login": time.mktime(res[3].timetuple()) * 1000,
					"locked": res[4] > 0
				})
			return ret

	def export_db_to_json(self, filename):
		"""Export the API db to a certain format JSON file"""
		with self.connect() as cursor:
			# Get summed size of all up-to-date APIs in the library
			sql = "SELECT IFNULL(SUM(size), 0), COUNT(*) FROM api WHERE display='Y'"
			cursor.execute(sql)
			resultset = cursor.fetchone()
			if resultset is None:
				try:
					os.remove(filename)  # Lose the export file if we don't have any APIs in storage
				except FileNotFoundError:
					pass
			ret = {
				"count": resultset[1],
				"totalCount": 0,
				"size": int(resultset[0]),
				"totalSize": 0
			}

			# Get count+size of ALL currently stored jar files
			for path, names, files in os.walk(self.jar_dir):
				for file in files:
					if not file.endswith(".jar"):
						continue
					f = os.path.join(path, file)
					ret["totalCount"] += 1
					ret["totalSize"] += os.path.getsize(f) / 1000000

			# Populate base API info
			sql = "SELECT id, term, year FROM api WHERE display='Y'"
			cursor.execute(sql)
			resultset = cursor.fetchall()
			# Sort the result set; can't be done in the DB because of conditional logic involved in term ordering
			resultset = sorted(resultset, key=(lambda a: str(a[2] - 1 if a[1] > 'B' else a[2]) + a[1]), reverse=True)

			currTerm = None
			currYear = None
			index = -1
			ret["classes"] = []
			for api in resultset:
				apiInfo = self.get_api_info(api_id=api[0])
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

	def __get_image_name(self, api_id):
		with self.connect() as cursor:
			cursor.execute("SELECT image_url FROM api WHERE id=%s", api_id)
			return cursor.fetchone()[0]

	def __get_image_file_loc(self, api_id):
		for file in os.listdir(self.img_dir):
			if file.startswith(api_id):
				return os.path.join(self.img_dir, file)
		return None

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
