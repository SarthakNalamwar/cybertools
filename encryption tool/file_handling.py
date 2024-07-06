def read_file(file_path):
    with open(file_path, 'r') as file:
        return file.read()

def write_file(file_path, content):
    with open(file_path, 'w') as file:
        file.write(content)

def read_binary_file(file_path):
    with open(file_path, 'rb') as file:
        return file.read()

def write_binary_file(file_path, content):
    with open(file_path, 'wb') as file:
        file.write(content)
