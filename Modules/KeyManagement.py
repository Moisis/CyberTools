class KeyManagement:
    @staticmethod
    def save_key(filename, key):
        with open(filename, 'wb') as f:
            f.write(key)

    @staticmethod
    def load_key(filename):
        with open(filename, 'rb') as f:
            return f.read()
