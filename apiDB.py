import os
import re
import html
import uuid
import time
import json
import base64
import magic
import pymysql
from bcrypt import hashpw, gensalt, checkpw


class APIDatabase:
	def __init__(self, host, port, user, password, schema, img_dir, jar_dir):
		self.connection = pymysql.connect(
			host=host,
			port=port,
			user=user,
			password=password,
			database=schema
		)
		self.cursor = self.connection.cursor()

		sql = "CREATE TABLE IF NOT EXISTS user (" \
				"username    VARCHAR(32)   PRIMARY KEY, " \
				"password    CHAR(60)      NOT NULL)"
		self.cursor.execute(sql)

		sql = "CREATE TABLE IF NOT EXISTS api (" \
				"id CHAR(36) PRIMARY KEY, " \
				"name        VARCHAR(64)   NOT NULL, " \
				"contact     VARCHAR(128), " \
				"artifactID  VARCHAR(64), " \
				"groupID     VARCHAR(64), " \
				"version     VARCHAR(8)    NOT NULL, " \
				"size        INT, " \
				"description TEXT, " \
				"term        CHAR(1)       NOT NULL, " \
				"year        INT           NOT NULL, " \
				"team        CHAR(1)       NOT NULL, " \
				"lastupdate  TIMESTAMP     DEFAULT CURRENT_TIMESTAMP, " \
				"creator     VARCHAR(32)   NOT NULL, " \
				"display	 CHAR(1)	   DEFAULT 'Y', " \
				"CONSTRAINT uniq_artifact UNIQUE(artifactID, groupID))"
		self.cursor.execute(sql)

		sql = "CREATE TABLE IF NOT EXISTS version (" \
				"apiId       CHAR(36)      NOT NULL, " \
				"vnumber     VARCHAR(16)   NOT NULL, " \
				"info        TEXT, " \
				"CONSTRAINT FOREIGN KEY idref(apiId) REFERENCES api(id) ON DELETE CASCADE, " \
				"CONSTRAINT uniq_version UNIQUE(apiId, vnumber));"

		self.cursor.execute(sql)
		self.connection.commit()

		self.imgdir = img_dir
		self.jardir = jar_dir

	def __del__(self):
		self.cursor.close()
		self.connection.close()

	def register_user(self, username, password):
		"""Add a user to the database, if they don't already exist."""
		if self.check_user_exists(username):
			return False

		sql = "INSERT INTO user (username, password) VALUES(%s, %s)"
		self.cursor.execute(sql, (username, hashpw(password, gensalt())))
		self.connection.commit()
		return True

	def delete_user(self, username):
		"""Delete a user from the database"""
		self.cursor.execute("UPDATE api SET creator=NULL, display='N' WHERE creator=%s", username)
		self.cursor.execute("DELETE FROM user WHERE username=%s", username)
		self.connection.commit()

	def authenticate(self, username, password):
		"""Authenticate username/password combo, just returns true/false"""
		sql = "SELECT password FROM user WHERE username=%s"
		self.cursor.execute(sql, username)
		res = self.cursor.fetchone()
		if res is None:
			return False

		return checkpw(password, res[0])

	def check_user_exists(self, username):
		"""Verify that a user exists; helper function for JWT authentication"""
		sql = "SELECT * FROM user WHERE username=%s"
		self.cursor.execute(sql, username)
		return self.cursor.fetchone() is not None

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

		# Create base entry in master API table
		sql = "INSERT INTO api (id, name, version, contact, description, creator, artifactID, groupID, term, year, team) " \
			"VALUES(%s, %s, '1.0.0', %s, %s, %s, %s, %s, %s, %s, %s)"
		apiID = str(uuid.uuid4())
		try:
			self.cursor.execute(sql, (apiID, name, contact, description, username, artifactID, groupID, term, year, team))
		except pymysql.IntegrityError:
			return False, "API with that artifact+groupID already exists, try changing your API's name"
		self.connection.commit()

		# TODO Create function for updating JSON file

		return True, apiID

	def update_api(self, username, api_id, **kwargs):
		"""Update an API entry... anything about it. Returns whether operation succeeded, false+msg if it didn't"""

		# VERIFICATION

		# Verify ownership of API
		self.cursor.execute("SELECT creator FROM api WHERE id=%s", api_id)
		res = self.cursor.fetchone()
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
			self.cursor.execute(sql, (kwargs[key], api_id))

		# Image processing: decode b64-encoded images, store them in img/directory for now, using API ID
		mime = magic.Magic(mime=True)
		if "image" in kwargs.keys():
			data = base64.standard_b64decode(kwargs["image"])
			mtype = mime.from_buffer(data)
			if mtype.find("image/") != -1:
				if self.__get_image_name(api_id) is not None:
					os.remove(self.__get_image_name(api_id))
				filename = os.path.join(self.imgdir, api_id + "." + mtype[mtype.find("/") + 1:])
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
				self.connection.rollback()
				return False, "Received file for API but it wasn't a jar file!"

			# Update version, size, timestamp
			sql = "UPDATE api SET version=%s, size=%s, lastupdate=CURRENT_TIMESTAMP() WHERE id=%s"
			vstring = re.search("\d+\.\d+\.\d+", kwargs["version"]).group(0)  # Safe because we already validated it
			self.cursor.execute(sql, (vstring, len(data) / 1000000, api_id))

			# Add version string to new entry in version table
			sql = "INSERT INTO version(apiId, vnumber, info) VALUES (%s, %s, %s)"
			try:
				self.cursor.execute(sql, (api_id, vstring, html.escape(kwargs["version"].replace(vstring, "").lstrip())))
			except pymysql.IntegrityError:
				self.connection.rollback()
				return False, "Failed to update API; duplicate version detected"

			filename = os.path.join(self.jardir, api_id + ".jar")
			with open(filename, "wb") as jar:
				jar.write(base64.standard_b64decode(kwargs["jar"]))

			# Install jar file into maven repository! Yeah, I do it with a system() command, sue me.
			sql = "SELECT groupID, artifactID FROM api WHERE id=%s"
			self.cursor.execute(sql, api_id)
			res = self.cursor.fetchone()
			os.system("mvn install:install-file -Dfile={} "
					  "-DgroupId={} "
					  "-DartifactId={} "
					  "-Dversion={} "
					  "-Dpackaging=jar "
					  "-DlocalRepositoryPath={}"
					  .format(filename, res[0], res[1], vstring, self.jardir))
			os.remove(filename)

		self.connection.commit()
		return True, "Updated API"

	def delete_api(self, username, api_id):
		"""Delete an API and its associated image. Jar files are left intact since others may rely on them."""

		# Verify the API actually exists and that this user owns it
		self.cursor.execute("SELECT creator FROM api WHERE id=%s AND display='Y'", api_id)
		res = self.cursor.fetchone()
		if res is None or res[0] != username:
			return False

		self.cursor.execute("UPDATE api SET display='N' WHERE id=%s", api_id)
		self.connection.commit()
		if self.__get_image_name(api_id) is not None:
			os.remove(self.__get_image_name(api_id))
		return True

	def get_api_id(self, group_id, artifact_id):
		"""Get an API's ID, required for database operations involving APIs"""
		sql = "SELECT id FROM api WHERE groupID=%s AND artifactID=%s AND display='Y'"
		self.cursor.execute(sql, (group_id, artifact_id))
		res = self.cursor.fetchone()
		if res is None:
			return None
		return res[0]

	def get_api_info(self, api_id):
		"""Get an API info dict using apiID or a groupID+artifactID combination"""
		# Get basic API info
		sql = "SELECT name, contact, artifactID, groupID, version, description, lastupdate, id, creator, size, " \
			"term, year, team FROM api WHERE id=%s AND display='Y'"
		self.cursor.execute(sql, api_id)
		res = self.cursor.fetchone()
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
		sql = "SELECT vnumber, info FROM version WHERE apiID=%s ORDER BY vnumber DESC"
		self.cursor.execute(sql, api_id)
		res = self.cursor.fetchall()
		vlist = []
		if res is not None and len(res) > 0:
			for version in res:
				vlist.append(version[0] + ": " + version[1])

		ret["history"] = vlist
		return ret

	def export_db_to_json(self, filename):
		"""Export the API db to a certain format JSON file"""

		# Get summed size of all up-to-date APIs in the library
		sql = "SELECT IFNULL(SUM(size), 0), COUNT(*) FROM api WHERE display='Y'"
		self.cursor.execute(sql)
		resultset = self.cursor.fetchone()
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
		for path, names, files in os.walk(self.jardir):
			for file in files:
				if not file.endswith(".jar"):
					continue
				f = os.path.join(path, file)
				ret["totalCount"] += 1
				ret["totalSize"] += os.path.getsize(f) / 1000000

		# Populate base API info
		sql = "SELECT id, term, year FROM api WHERE display='Y'"
		self.cursor.execute(sql)
		resultset = self.cursor.fetchall()
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
		for file in os.listdir(self.imgdir):
			if file.startswith(api_id):
				return os.path.join(self.imgdir, file)
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
