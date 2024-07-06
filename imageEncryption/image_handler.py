from PIL import Image
import io

def load_image(file_path: str) -> bytes:
    with open(file_path, "rb") as img_file:
        return img_file.read()

def save_image(image_data: bytes, file_path: str):
    with open(file_path, "wb") as img_file:
        img_file.write(image_data)

def display_image(image_data: bytes):
    image = Image.open(io.BytesIO(image_data))
    image.show()
