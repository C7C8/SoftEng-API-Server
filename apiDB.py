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
		"""Create an API entry. Returns the API's ID"""

		# Create base entry in master API table
		sql = "INSERT INTO api (id, name, version, contact, description, creator) VALUES(%s, %s, '1.0.0', %s, %s, %s)"
		id = str(uuid.uuid4())
		self.cursor.execute(sql, (id, name, contact, description, username))
		self.connection.commit()

		# Create single entry in version table
		sql = "INSERT INTO version(apiId, info) VALUES (%s, %s)"
		self.cursor.execute(sql, (id, "1.0.0 Initial release"))
		# TODO Create function for updating JSON file

		return id
