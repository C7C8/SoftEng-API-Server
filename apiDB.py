import pymysql
import uuid
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

	def updateAPI(self, apiID, **kwargs):
		"""Update an API entry... anything about it. Returns whether operation succeeded"""
		# Verify the API actually exists
		self.cursor.execute("SELECT id FROM api WHERE id=%s", apiID)
		if len(self.cursor.fetchall()) == 0:
			return False

		# I know, I know, I checked this over in app.py... this check ensures function can be used elsewhere, though
		allowed = ("name", "version", "size", "contact", "description")
		if not all(arg in allowed for arg in kwargs.keys()):
			return False

		# Slightly hacky: The arguments in the args dict are the same as the column names in the database API table...
		# OH YEAH! Just iterate over every key, substituting in its name for the update, and the corresponding data
		for key in kwargs.keys():
			if key == "version":
				continue
			sql = "UPDATE api SET {}=%s WHERE id=%s".format(key)
			self.cursor.execute(sql, (kwargs[key], apiID))

		# Add new version to the list
		if "version" in kwargs.keys():
			sql = "INSERT INTO version(apiId, info) VALUES (%s, %s)"
			self.cursor.execute(sql, (apiID, kwargs["version"]))

		self.connection.commit()
		return True
