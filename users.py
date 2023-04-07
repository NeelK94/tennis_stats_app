'''
import sqlite3

conn = sqlite3.connect("tennis.db")

# define columns to be used when creating players table
user_columns = [
    "id INTEGER PRIMARY KEY",
    "username VARCHAR UNIQUE",
    "password VARCHAR",
    "email VARCHAR"
]

# Create table for players
conn.execute(f"CREATE TABLE players ({','.join(user_columns)})")
cur = conn.cursor()


# Populate users initially
users_db = [
    "11111, 'NeelPeel', 'Iliketennis123', 'neel-k94@hotmail.com'",
    "11112, 'Antipesto', 'password11', 'adil.khokhar@yahoo.com'",
    "11113, 'BunceyTheCat', 'Iamacat!!', 'big.boosh@gmail.com'"
]

for user in users_db:
    conn.execute(f"INSERT INTO players VALUES ({user})")

conn.commit()

cur.execute("SELECT * FROM players")

for person in cur.fetchall():
    print(person)
'''

users = {
    "111111": {
        "username": "NeelPeel",
        "password": "Iliketennis123",
        "email": "neel-k94@hotmail.com"
    },
    "111112": {
        "username": "Antipesto",
        "password": "password11",
        "email": "adil.khokhar@yahoo.com"
    },
    "111113": {
        "username": "BunceyTheCat",
        "password": "Iamacat!!",
        "email": "big.boosh@gmail.com"
    }
}


def read_all():
    return list(users.values())
