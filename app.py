from tkinter import *
from tkinter import ttk, filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from PIL import Image
import io
import hashlib

# Function to encrypt the image
def encrypt_image(key, in_filename, out_filename):
    try:
        # Create a new AES cipher object with the key
        cipher = AES.new(key, AES.MODE_CBC)
        # Open the input file in read-binary mode
        with open(in_filename, 'rb') as f:
            plaintext = f.read()
        # Encrypt the plaintext
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
        # Open the output file in write-binary mode
        with open(out_filename, 'wb') as f:
            # Write the initialization vector and the ciphertext to the output file
            f.write(cipher.iv)
            f.write(ciphertext)
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Function to decrypt the image
def decrypt_image(key, in_filename, out_filename):
    try:
        # Open the input file in read-binary mode
        with open(in_filename, 'rb') as f:
            # Read the initialization vector and the ciphertext
            iv = f.read(16)
            ciphertext = f.read()
        # Create a new AES cipher object with the key and the initialization vector
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        # Decrypt the ciphertext
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        # Open the output file in write-binary mode
        with open(out_filename, 'wb') as f:
            # Write the plaintext to the output file
            f.write(plaintext)
    except Exception as e:
        messagebox.showerror("Error", "Decryption failed. Check your password and ensure the encrypted file has not been altered.")

# Function to load an image
def load_image():
    filename = filedialog.askopenfilename()
    return filename

# Function to save an image
def save_image():
    filename = filedialog.asksaveasfilename(defaultextension=".png")
    return filename

# Main function
def main():
    window = Tk()
    window.title("Image Encryptor/Decryptor")
    style = ttk.Style()
    style.theme_use('clam')

    password = StringVar()

    ttk.Label(window, text="Password").grid(row=0)
    ttk.Entry(window, textvariable=password, show="*").grid(row=0, column=1)

    ttk.Button(window, text="Encrypt Image", command=lambda: encrypt_image(hashlib.sha256(password.get().encode()).digest(), load_image(), save_image())).grid(row=1, column=0)
    ttk.Button(window, text="Decrypt Image", command=lambda: decrypt_image(hashlib.sha256(password.get().encode()).digest(), load_image(), save_image())).grid(row=1, column=1)

    window.mainloop()

if __name__ == "__main__":
    main()
