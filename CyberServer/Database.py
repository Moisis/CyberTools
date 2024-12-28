import psycopg2


class PostgresDB:
    def __init__(self, db_name, user, password, host="localhost", port=5432):
        """
        Initialize the PostgresDB class.
        :param db_name: Name of the database
        :param user: Database user
        :param password: Database password
        :param host: Database host (default: localhost)
        :param port: Database port (default: 5432)
        """
        self.db_name = db_name
        self.user = user
        self.password = password
        self.host = host
        self.port = port
        self.connection = None
        self.cursor = None

    def connect(self):
        """Establish a connection to the PostgreSQL database."""
        try:
            self.connection = psycopg2.connect(
                dbname=self.db_name,
                user=self.user,
                password=self.password,
                host=self.host,
                port=self.port
            )
            self.cursor = self.connection.cursor()
            print("Connected to the database successfully.")
        except psycopg2.Error as e:
            print(f"Error connecting to the database: {e}")

    def insert_user(self, username, password, email, public_key, device_id):
        """Insert a new user into the 'users' table."""
        try:
            insert_query = ("INSERT INTO users (username, password, email, public_key, device_id) VALUES (%s, %s, %s, "
                            "%s, %s);")
            self.cursor.execute(insert_query, (username, password, email, public_key, device_id))
            self.connection.commit()
            print(f"User '{username}' added successfully.")
        except psycopg2.Error as e:
            print(f"Error inserting user: {e}")

    def fetch_users(self):
        """Fetch all users from the 'users' table."""
        try:
            fetch_query = "SELECT id, username FROM users;"
            self.cursor.execute(fetch_query)
            users = self.cursor.fetchall()
            return users
        except psycopg2.Error as e:
            print(f"Error fetching users: {e}")
            return []

    def get_user_password(self, username):
        """Fetch the password for a specific user."""
        try:
            fetch_query = "SELECT password FROM users WHERE username = %s;"
            self.cursor.execute(fetch_query, (username,))
            password = self.cursor.fetchone()
            return password[0] if password else None
        except psycopg2.Error as e:
            print(f"Error fetching user password: {e}")
            return None

    def close(self):
        """Close the database connection."""
        if self.cursor:
            self.cursor.close()
        if self.connection:
            self.connection.close()
        print("Database connection closed.")

    def get_client_public_key(self, username):
        """Fetch the public key of a client from the database."""
        try:
            fetch_query = "SELECT public_key FROM users WHERE username = %s;"
            self.cursor.execute(fetch_query, (username,))
            public_key = self.cursor.fetchone()
            return public_key[0] if public_key else None
        except psycopg2.Error as e:
            print(f"Error fetching client public key: {e}")
            return None

    def insert_text(self, sender, recipient, title, encrypted_text, text_hash, encrypted_key, tag, nonce):
        """Insert a new text message into the 'texts' table."""
        try:
            insert_query = """
            INSERT INTO texts 
            (sender, recipient, title, encrypted_text, text_hash, encrypted_key, tag, nonce)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id;"""

            self.cursor.execute(insert_query, (
                sender, recipient, title, encrypted_text,
                text_hash, encrypted_key, tag, nonce
            ))
            text_id = self.cursor.fetchone()[0]
            self.connection.commit()
            return text_id
        except psycopg2.Error as e:
            print(f"Error inserting text: {e}")
            return None

    def get_texts_for_user(self, recipient):
        """Fetch all texts for a specific recipient."""
        try:
            fetch_query = """
            SELECT id, sender, title 
            FROM texts 
            WHERE recipient = %s 
            ORDER BY timestamp DESC;"""

            self.cursor.execute(fetch_query, (recipient,))
            return self.cursor.fetchall()
        except psycopg2.Error as e:
            print(f"Error fetching texts for user: {e}")
            return []

    def get_text_content(self, text_id, recipient):
        """Fetch the content of a specific text message."""
        try:
            fetch_query = """
            SELECT sender, encrypted_text, text_hash, encrypted_key, tag, nonce 
            FROM texts 
            WHERE id = %s AND recipient = %s;"""

            self.cursor.execute(fetch_query, (text_id, recipient))
            return self.cursor.fetchone()
        except psycopg2.Error as e:
            print(f"Error fetching text content: {e}")
            return None
