import os
import re
import uuid
import time
import json
import base64
import magic
import pymysql
from bcrypt import hashpw, gensalt, checkpw


class APIDatabase:
	def __init__(self, imgdir, jardir):
		self.connection = pymysql.connect(
			host="localhost",
			port=3306,
			user="list-api-service",
			password="pass",
			database="apilist"
		)
		self.cursor = self.connection.cursor()

		self.imgdir = imgdir
		self.jardir = jardir

	def __del__(self):
		self.cursor.close()
		self.connection.close()

	def registerUser(self, username, password, term, year, team):
		"""Add a user to the database, if they don't already exist."""
		sql = "SELECT username FROM users WHERE username=%s"
		self.cursor.execute(sql, username)
		if len(self.cursor.fetchall()) > 0:
			return False

		sql = "INSERT INTO users (username, password, term, year, team) VALUES(%s, %s, %s, %s, %s)"
		self.cursor.execute(sql, (username, hashpw(password, gensalt()), term, year, team))
		self.connection.commit()
		return True

	def deleteUser(self, username):
		"""Delete a user from the database"""
		sql = "DELETE FROM users WHERE username=%s"
		self.cursor.execute(sql, username)
		self.connection.commit()

	def authenticate(self, username, password):
		"""Authenticate username/password combo, just returns true/false"""
		sql = "SELECT password FROM users WHERE username=%s"
		self.cursor.execute(sql, username)
		res = self.cursor.fetchone()
		if type(res) is None:
			return False

		return checkpw(password, res[0])

	def createAPI(self, username, name, contact, description):
		"""Create base API entry, returns API ID on success"""

		# Calculate artifact ID and group ID
		artifactID = name.replace(" ", "")
		sql = "SELECT term, year, team FROM users WHERE username=%s"
		self.cursor.execute(sql, username)
		res = self.cursor.fetchone()
		if res is None:
			return "error"
		groupID = res[0].lower() + str(res[1])[2:] + ".team" + res[2].upper()

		# Create base entry in master API table
		sql = "INSERT INTO api (id, name, version, contact, description, creator, artifactID, groupID) " \
			"VALUES(%s, %s, '1.0.0', %s, %s, %s, %s, %s)"
		apiID = str(uuid.uuid4())
		self.cursor.execute(sql, (apiID, name, contact, description, username, artifactID, groupID))
		self.connection.commit()

		# TODO Create function for updating JSON file

		return apiID

	def updateAPI(self, username, apiID, **kwargs):
		"""Update an API entry... anything about it. Returns whether operation succeeded, false+msg if it didn't"""
		# Verify ownership of API
		self.cursor.execute("SELECT creator FROM api WHERE id=%s", apiID)
		vres = self.cursor.fetchone()
		if vres is None or vres[0] != username:
			return False, "Couldn't verify user ownership of API"

		# Since these values are basically passed in RAW into the db, it's critical to allow only select keywords
		allowed = ("name", "version", "contact", "description", "image", "jar")
		if not all(arg in allowed for arg in kwargs.keys()):
			return False, "Illegal API change argument"

		# Slightly hacky: The arguments in the args dict are the same as the column names in the database API table...
		# OH YEAH! Just iterate over every key, substituting in its name for the update, and the corresponding data
		for key in kwargs.keys():
			if key == "version" or key == "image" or key == "jar":
				continue
			sql = "UPDATE api SET {}=%s WHERE id=%s".format(key)
			self.cursor.execute(sql, (kwargs[key], apiID))

		# Image processing: decode b64-encoded images, store them in img/directory for now, using API ID
		mime = magic.Magic(mime=True)
		if "image" in kwargs.keys():
			data = base64.standard_b64decode(kwargs["image"])
			mtype = mime.from_buffer(data)
			if mtype.find("image/") != -1:
				if self.__getImageName(apiID) is not None:
					os.remove(self.__getImageName(apiID))
				filename = os.path.join(self.imgdir, apiID + "." + mtype[mtype.find("/") + 1:])
				with open(filename, "wb") as image:
					image.write(data)
			else:
				print("Received image file for API " + apiID + ", but it wasn't an image!")

		# Jar processing: decode b64-encoded jar files, store them in work. Make sure that an appropriate version string
		# is provided, otherwise we can't add it to the repo. TODO Execute script to add jar files to Maven repository
		if "jar" in kwargs.keys() and "version" in kwargs.keys():
			data = base64.standard_b64decode(kwargs["jar"])
			if mime.from_buffer(data).find("application/zip") != -1:
				filename = os.path.join(self.jardir, apiID + ".jar")
				with open(filename, "wb") as jar:
					jar.write(base64.standard_b64decode(kwargs["jar"]))

				# Update lastupdate time, version, and size
				sql = "UPDATE api SET lastupdate=%s, version=%s, size=%s WHERE id=%s"
				vres = re.search("\d+\.\d+\.\d+", kwargs["version"])
				if vres is None:
					self.connection.rollback()
					return False, "Invalid version string, please provide versions formatted as #+.#+.#+ (e.g. 1.15.2)"
				self.cursor.execute(sql, (int(time.time()), vres.group(0), len(data) / 1000000, apiID))

				# Add version string to new entry in version table
				sql = "INSERT INTO version(apiId, info) VALUES (%s, %s)"
				self.cursor.execute(sql, (apiID, kwargs["version"]))
				self.cursor.execute("UPDATE api SET lastupdate=CURRENT_TIMESTAMP() WHERE id=%s", apiID)
			else:
				print("Received jar file for API " + apiID + ", but it wasn't a jar file!")

		self.connection.commit()
		return True, "Updated API"

	def deleteAPI(self, username, apiID):
		"""Delete an API and its associated image. Jar files are left intact since others may rely on them."""

		# Verify the API actually exists and that this user owns it
		self.cursor.execute("SELECT creator FROM api WHERE id=%s", apiID)
		res = self.cursor.fetchone()
		if res is None or res[0] != username:
			return False

		self.cursor.execute("DELETE FROM api WHERE id=%s", apiID)
		self.connection.commit()
		if self.__getImageName(apiID) is not None:
			os.remove(self.__getImageName(apiID))
		return True

	def getAPIInfo(self, apiID=None, groupID=None, artifactID=None):
		"""Get an API info dict using apiID or a groupID+artifactID combination"""
		# Get basic API info
		if apiID is None:
			sql = "SELECT name, contact, artifactID, groupID, version, description, lastupdate, id, creator, size " \
					"FROM api WHERE artifactID=%s AND groupID=%s"
			self.cursor.execute(sql, (artifactID, groupID))
		else:
			sql = "SELECT name, contact, artifactID, groupID, version, description, lastupdate, id, creator, size " \
					"FROM api WHERE id=%s"
			self.cursor.execute(sql, apiID)

		res = self.cursor.fetchone()
		if res is None:
			return None
		apiID = res[7]  # Just in case it groupID+artifactID were provided instead

		# Fill out base API info data structure
		ret = {
			"id": apiID,
			"name": res[0],
			"version": res[4],
			"size": res[9],
			"contact": res[1],
			"gradle": "[group: '{}', name: '{}', version:'{}']".format(res[3], res[2], res[4]),
			"description": res[5],
			"image": self.__getImageName(apiID),
			"last-update": time.mktime(res[6].timetuple())
		}

		# Get user data
		sql = "SELECT term, year, team FROM users WHERE username=%s"
		self.cursor.execute(sql, res[8])
		res = self.cursor.fetchone()
		ret["term"] = res[0]
		ret["year"] = res[1]
		ret["team"] = res[2]

		# Get version history
		sql = "SELECT info FROM version WHERE apiID=%s"
		self.cursor.execute(sql, apiID)
		res = self.cursor.fetchall()
		vlist = []
		if res is not None and len(res) > 0:
			for version in res:
				vlist.append(version[0])

		ret["history"] = vlist
		return ret

	def exportToJSON(self, filename):
		"""Export the API db to a certain format JSON file"""
		sql = "SELECT id, term, year FROM api, users WHERE creator=username"
		self.cursor.execute(sql)
		resultset = self.cursor.fetchall()
		if resultset is None:
			return

		# Sort the result set; can't be done in the DB because of conditional logic involved in term ordering
		resultset = sorted(resultset, key=(lambda a: str(a[2] - 1 if a[1] > 'B' else a[2]) + a[1]), reverse=True)

		ret = {
			"count": len(resultset),
		}

		# Get size of up-to-date API library
		sql = "SELECT SUM(size) FROM api"
		self.cursor.execute(sql)
		ret["size"] = int(self.cursor.fetchone()[0])

		# Get count+size of ALL currently stored jar files
		ret["totalCount"] = 0
		ret["totalSize"] = 0
		for path, names, files in os.walk(self.jardir):
			for file in files:
				if not file.endswith(".jar"):
					pass
				f = os.path.join(path, file)
				ret["totalCount"] += 1
				ret["totalSize"] += os.path.getsize(f) / 1000000

		# Populate base API info
		currTerm = None
		currYear = None
		index = -1
		ret["classes"] = []
		for api in resultset:
			apiInfo = self.getAPIInfo(apiID=api[0])
			if (apiInfo["term"] != currTerm) or (apiInfo["year"] != currYear):
				currTerm = apiInfo["term"]
				currYear = apiInfo["year"]
				index += 1
				ret["classes"].append({
					"term": currTerm,
					"year": currYear,
					"list": []
				})
			ret["classes"][index]["list"].append(apiInfo)

		with open(filename, "w") as out:
			out.write(json.dumps(ret))

	def __getImageName(self, apiID):
		for file in os.listdir(self.imgdir):
			if file.startswith(apiID):
				return os.path.join(self.imgdir, file)
		return None
