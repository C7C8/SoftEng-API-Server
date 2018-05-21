import re
import uuid
import time
import base64
import magic
import pymysql
from sqlalchemy.util import NoneType
from bcrypt import hashpw, gensalt, checkpw


class APIDatabase:
	def __init__(self):
		self.connection = pymysql.connect(
			host="localhost",
			port=3306,
			user="list-api-service",
			password="pass",
			database="apilist"
		)
		self.cursor = self.connection.cursor()

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
		if type(res) is NoneType:
			return False

		return checkpw(password, res[0])

	def createAPI(self, username, name, contact, description):
		"""Create an API entry. Returns the API's ID. Not allowed to provide a version string because it's automatically
		set to '1.0.0 Initial release'"""

		# Create base entry in master API table
		sql = "INSERT INTO api (id, name, version, contact, description, creator) VALUES(%s, %s, '1.0.0', %s, %s, %s)"
		apiID = str(uuid.uuid4())
		self.cursor.execute(sql, (apiID, name, contact, description, username))

		# Create single entry in version table
		sql = "INSERT INTO version(apiId, info) VALUES (%s, %s)"
		self.cursor.execute(sql, (apiID, "1.0.0 Initial release"))
		self.connection.commit()
		# TODO Create function for updating JSON file

		return apiID

	def updateAPI(self, username, apiID, **kwargs):
		"""Update an API entry... anything about it. Returns whether operation succeeded"""
		# Verify ownership of API
		self.cursor.execute("SELECT creator FROM api WHERE id=%s", apiID)
		res = self.cursor.fetchone()
		if type(res) == NoneType or res[0] != username:
			return False

		# Since these values are basically passed in RAW into the db, it's critical to verify only select keywords
		# are allowed through.
		allowed = ("name", "version", "contact", "description", "image", "jar")
		if not all(arg in allowed for arg in kwargs.keys()):
			return False

		# Slightly hacky: The arguments in the args dict are the same as the column names in the database API table...
		# OH YEAH! Just iterate over every key, substituting in its name for the update, and the corresponding data
		for key in kwargs.keys():
			if key == "version" or key == "image" or key == "jar":
				continue
			sql = "UPDATE api SET {}=%s WHERE id=%s".format(key)
			self.cursor.execute(sql, (kwargs[key], apiID))

		# Image processing: deocde b64-encoded images, store them in img/directory for now, using API ID
		mime = magic.Magic(mime=True)
		if "image" in kwargs.keys():
			data = base64.standard_b64decode(kwargs["image"])
			mtype = mime.from_buffer(data)
			if mtype.find("image/") != -1:
				filename = "img/" + apiID + "." + mtype[mtype.find("/")+1:]
				with open(filename, "wb") as image:
					image.write(data)
			else:
				print("Received image file for API " + apiID + ", but it wasn't an image!")

		# Jar processing: decode b64-encoded jar files, store them in work. Make sure that an appropriate version string
		# is provided, otherwise we can't add it to the repo. TODO Execute script to add jar files to Maven repository
		if "jar" in kwargs.keys() and "version" in kwargs.keys():
			data = base64.standard_b64decode(kwargs["jar"])
			if mime.from_buffer(data).find("application/zip") != -1:
				filename = "jar/" + apiID + ".jar"
				with open(filename, "wb") as jar:
					jar.write(base64.standard_b64decode(kwargs["jar"]))

				# Update lastupdate time and version
				sql = "UPDATE api SET lastupdate=%s, version=%s WHERE id=%s"
				self.cursor.execute(sql, (time.time(), re.search("\d+\.\d+\.\d+", kwargs["version"]).group(0), apiID))


				# Add version string to new entry in version table
				sql = "INSERT INTO version(apiId, info) VALUES (%s, %s)"
				self.cursor.execute(sql, (apiID, kwargs["version"]))
				self.cursor.execute("UPDATE api SET lastupdate=CURRENT_TIMESTAMP() WHERE id=%s", apiID)
			else:
				print("Received jar file for API " + apiID + ", but it wasn't a jar file!")

		self.connection.commit()
		return True

	def deleteAPI(self, username, apiID):
		# Verify the API actually exists and that this user owns it
		self.cursor.execute("SELECT creator FROM api WHERE id=%s", apiID)
		res = self.cursor.fetchone()
		if len(res) == 0 or res[0] != username:
			return False

		self.cursor.execute("DELETE FROM api WHERE id=%s", apiID)
		self.connection.commit()
		return True
