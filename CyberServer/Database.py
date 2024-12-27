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
