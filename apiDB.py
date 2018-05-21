import pymysql
import uuid
import base64
import magic
import os
from bcrypt import hashpw, gensalt, checkpw
from sqlalchemy.util import NoneType


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
		id = str(uuid.uuid4())
		self.cursor.execute(sql, (id, name, contact, description, username))

		# Create single entry in version table
		sql = "INSERT INTO version(apiId, info) VALUES (%s, %s)"
		self.cursor.execute(sql, (id, "1.0.0 Initial release"))
		self.connection.commit()
		# TODO Create function for updating JSON file

		return id

	def updateAPI(self, username, apiID, **kwargs):
		"""Update an API entry... anything about it. Returns whether operation succeeded"""
		# Verify the API actually exists and that this user owns it
		self.cursor.execute("SELECT creator FROM api WHERE id=%s", apiID)
		res = self.cursor.fetchone()
		if type(res) == NoneType or res[0] != username:
			return False

		# I know, I know, I checked this over in app.py... this check ensures function can be used elsewhere, though
		allowed = ("name", "version", "size", "contact", "description", "image", "jar")
		if not all(arg in allowed for arg in kwargs.keys()):
			return False

		# Slightly hacky: The arguments in the args dict are the same as the column names in the database API table...
		# OH YEAH! Just iterate over every key, substituting in its name for the update, and the corresponding data
		for key in kwargs.keys():
			if key == "version" or key == "image" or key == "image-type":
				continue
			sql = "UPDATE api SET {}=%s WHERE id=%s".format(key)
			self.cursor.execute(sql, (kwargs[key], apiID))

		# Add new version to the list
		if "version" in kwargs.keys():
			sql = "INSERT INTO version(apiId, info) VALUES (%s, %s)"
			self.cursor.execute(sql, (apiID, kwargs["version"]))
			self.cursor.execute("UPDATE api SET lastupdate=CURRENT_TIMESTAMP() WHERE id=%s", apiID)

		self.connection.commit()

		# Image processing: extract images, store them in working directory for now, store by API ID
		mime = magic.Magic(mime=True)
		if "image" in kwargs.keys():
			filename = "img/" + apiID
			print(filename)
			with open(filename, "wb") as image:
				image.write(base64.standard_b64decode(kwargs["image"]))

			# Apply appropriate file extension, otherwise delete non-image files
			print(mime.from_file(filename))
			mtype = mime.from_file(filename)
			if mtype.find("image/") == -1:
				os.remove(filename)
			else:
				os.rename(filename, filename + "." + mtype[mtype.find("/")+1:])

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
