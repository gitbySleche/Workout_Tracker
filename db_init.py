import sqlite3 

con = sqlite3.connect('workouts.db')
cursor = con.cursor()

cursor.execute('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT NOT NULL, email TEXT NOT NULL, password TEXT NOT NULL)')
cursor.execute('CREATE TABLE IF NOT EXISTS workouts(id INTEGER PRIMARY KEY, title TEXT, user_id INTEGER NOT NULL, exercise_id INTEGER NOT NULL, FOREIGN KEY (user_id) REFERENCES users(id), FOREIGN KEY (exercise_id) REFERENCES exercises(id))')
cursor.execute('CREATE TABLE IF NOT EXISTS exercises(id INTEGER PRIMARY KEY, workout_id INTEGER NOT NULL, sets INTEGER NOT NULL, reps INTEGER NOT NULL, weights FLOAT, FOREIGN KEY (workout_id) REFERENCES workouts(id))')
cursor.execute('CREATE TABLE IF NOT EXISTS scheduling(id INTEGER PRIMARY KEY, workout_id INTEGER NOT NULL, schedule_at TIMESTAMP NOT NULL, completed_at TIMESTAMP, FOREIGN KEY (workout_id) REFERENCES workouts(id))')
con.commit()
con.close()