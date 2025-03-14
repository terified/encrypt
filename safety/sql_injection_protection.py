import sqlite3

def create_connection(db_file):
    conn = sqlite3.connect(db_file)
    return conn

def execute_query(conn, query, params):
    cur = conn.cursor()
    cur.execute(query, params)
    conn.commit()

def fetch_query(conn, query, params):
    cur = conn.cursor()
    cur.execute(query, params)
    return cur.fetchall()

def add_user(conn, username, password):
    query = "INSERT INTO users (username, password) VALUES (?, ?)"
    params = (username, password)
    execute_query(conn, query, params)

def get_user(conn, username):
    query = "SELECT * FROM users WHERE username = ?"
    params = (username,)
    return fetch_query(conn, query, params)

def main():
    database = "test.db"
    conn = create_connection(database)
    add_user(conn, "test_user", "test_password")
    user = get_user(conn, "test_user")
    print(user)

if __name__ == '__main__':
    main()