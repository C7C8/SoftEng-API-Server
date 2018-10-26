import os
import re
import html
import uuid
import time
import json
import base64
from distutils.version import StrictVersion

import magic
import pymysql
from bcrypt import hashpw, gensalt, checkpw


class APIDatabase:
	def __init__(self, host, port, user, password, database, img_dir, jar_dir):
		self.__dict__.update({k: v for k, v in locals().items() if k != 'self'})

	def connect(self):
		return pymysql.connect(**{k: v for k, v in self.__dict__.items() if k != 'img_dir' and k != 'jar_dir'}).cursor()

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

	def authenticate(self, username, password):
		"""Authenticate username/password combo, returns tuple of booleans (one for auth, second for admin rights"""
		with self.connect() as cursor:
			cursor.execute("SELECT password, admin FROM user WHERE username=%s", username)
			res = cursor.fetchone()
			if res is None:
				return False, False

		return checkpw(password, res[0]), res[1] > 0

	def is_admin(self, username):
		with self.connect() as cursor:
			try:
				cursor.execute("SELECT admin FROM user WHERE username=%s", username)
				res = cursor.fetchone()
				if res is None:
					return False

				return res[0] > 0
			except:
				return False

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
					if self.__get_image_name(api_id) is not None:
						os.remove(self.__get_image_file_loc(api_id))
					filename = os.path.join(self.img_dir, api_id + "." + mtype[mtype.find("/") + 1:])
					with open(filename, "wb") as image:
						image.write(data)
				else:
					print("Received image file for API " + api_id + ", but it wasn't an image!")

			# Jar processing: decode b64-encoded jar files, store them in work. Make sure that an appropriate version string
			# is provided, otherwise we can't add it to the repo.
			if "jar" in kwargs.keys() and "version" in kwargs.keys():
				data = base64.standard_b64decode(kwargs["jar"])
				file_type = mime.from_buffer(data)
				if file_type.find("application/zip") == -1 and file_type.find('application/java-archive') == -1:
					cursor.connection.rollback()
					return False, "Received file for API but it wasn't a jar file!"

				# Update version, size, timestamp
				sql = "UPDATE api SET version=%s, size=%s, lastupdate=CURRENT_TIMESTAMP() WHERE id=%s"
				vstring = re.search("\d+\.\d+\.\d+", kwargs["version"]).group(0)  # Safe because we already validated it
				cursor.execute(sql, (vstring, len(data) / 1000000, api_id))

				# Add version string to new entry in version table
				sql = "INSERT INTO version(apiId, vnumber, info) VALUES (%s, %s, %s)"
				try:
					cursor.execute(sql, (api_id, vstring, kwargs["version"].replace(vstring, "").lstrip()))
				except pymysql.IntegrityError:
					cursor.connection.rollback()
					return False, "Failed to update API; duplicate version detected"

				filename = os.path.join(self.jar_dir, api_id + ".jar")
				with open(filename, "wb") as jar:
					jar.write(base64.standard_b64decode(kwargs["jar"]))

				# Install jar file into maven repository! Yeah, I do it with a system() command, sue me.
				sql = "SELECT groupID, artifactID FROM api WHERE id=%s"
				cursor.execute(sql, api_id)
				res = cursor.fetchone()
				os.system("mvn install:install-file -Dfile={} "
					  "-DgroupId={} "
					  "-DartifactId={} "
					  "-Dversion={} "
					  "-Dpackaging=jar "
					  "-DlocalRepositoryPath={}"
					  .format(filename, res[0], res[1], vstring, self.jar_dir))
				os.remove(filename)

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
			if self.__get_image_name(api_id) is not None:
				os.remove(self.__get_image_file_loc(api_id))
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

			with open(filename, "w") as out:
				out.write(json.dumps(ret))

	def __get_image_name(self, api_id):
		for file in os.listdir(self.img_dir):
			if file.startswith(api_id):
				return os.path.join(os.path.basename(self.img_dir), file)
		return None

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
