# Basic user authentication (for demonstration)
authorized_users = {'sarthak': 'sarthak', 'admin': 'admin'}

def authenticate(username, password):
    return authorized_users.get(username) == password
