import argparse
from encryption import aes_encrypt, aes_decrypt, des_encrypt, des_decrypt, rsa_encrypt, rsa_decrypt
from key_management import generate_aes_key, generate_des_key, generate_rsa_keys
from file_handling import read_file, write_file, read_binary_file, write_binary_file
from user_auth import authenticate
from utils import log_info, log_error
from Crypto.PublicKey import RSA

def main():
    parser = argparse.ArgumentParser(description="Cybersecurity Encryption Project")
    parser.add_argument('operation', choices=['encrypt', 'decrypt'], help='Operation to perform: encrypt or decrypt')
    parser.add_argument('algorithm', choices=['aes', 'des', 'rsa'], help='Encryption algorithm to use')
    parser.add_argument('input', help='Input text or file path')
    parser.add_argument('--output', help='Output file path', default='output.txt')
    parser.add_argument('--key', help='Key file path')
    parser.add_argument('--username', help='Username for authentication')
    parser.add_argument('--password', help='Password for authentication')

    args = parser.parse_args()

    # User authentication
    if not authenticate(args.username, args.password):
        log_error("Authentication failed.")
        return

    try:
        # Read input text or file
        input_text = read_file(args.input)

        if args.operation == 'encrypt':
            if args.algorithm == 'aes':
                key = generate_aes_key()
                nonce, ciphertext, tag = aes_encrypt(input_text, key)
                write_file(args.output, f'{nonce.hex()}:{ciphertext.hex()}:{tag.hex()}')
                write_binary_file(f'{args.output}.key', key)
            elif args.algorithm == 'des':
                key = generate_des_key()
                nonce, ciphertext, tag = des_encrypt(input_text, key)
                write_file(args.output, f'{nonce.hex()}:{ciphertext.hex()}:{tag.hex()}')
                write_binary_file(f'{args.output}.key', key)
            elif args.algorithm == 'rsa':
                private_key, public_key = generate_rsa_keys()
                ciphertext = rsa_encrypt(input_text, RSA.import_key(public_key))
                write_file(args.output, f'{public_key.decode()}::{ciphertext.hex()}')
                write_binary_file(f'{args.output}.key', private_key)

        elif args.operation == 'decrypt':
            if args.algorithm == 'aes':
                key = read_binary_file(args.key)
                nonce, ciphertext, tag = [bytes.fromhex(x) for x in read_file(args.input).split(':')]
                plaintext = aes_decrypt(nonce, ciphertext, tag, key)
                write_file(args.output, plaintext)
            elif args.algorithm == 'des':
                key = read_binary_file(args.key)
                nonce, ciphertext, tag = [bytes.fromhex(x) for x in read_file(args.input).split(':')]
                plaintext = des_decrypt(nonce, ciphertext, tag, key)
                write_file(args.output, plaintext)
            elif args.algorithm == 'rsa':
                private_key = RSA.import_key(read_binary_file(args.key))
                public_key, ciphertext_hex = read_file(args.input).split('::')
                ciphertext = bytes.fromhex(ciphertext_hex)
                plaintext = rsa_decrypt(ciphertext, private_key)
                write_file(args.output, plaintext)

        log_info(f"{args.operation.capitalize()}ion with {args.algorithm.upper()} completed successfully.")
    except Exception as e:
        log_error(f"An error occurred: {e}")

if __name__ == '__main__':
    main()
