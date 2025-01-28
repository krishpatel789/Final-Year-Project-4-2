#!/usr/bin/env python
# ----------------- Header Files ---------------------#

from __future__ import division, print_function, unicode_literals

import sys
import random
import argparse
import logging
from tkinter import *
from tkinter import filedialog
from tkinter import messagebox
import os
from PIL import Image
import math
from Crypto.Cipher import AES
import hashlib
import binascii
import numpy as np

global password 

def load_image(name):
    return Image.open(name)

# ----------------- Functions for encryption ---------------------#
def prepare_message_image(image, size):
    if size != image.size:
        image = image.resize(size, Image.ANTIALIAS)
    return image

def generate_secret(size, secret_image=None):
    width, height = size
    new_secret_image = Image.new(mode="RGB", size=(width * 2, height * 2))

    for x in range(0, 2 * width, 2):
        for y in range(0, 2 * height, 2):
            color1 = np.random.randint(255)
            color2 = np.random.randint(255)
            color3 = np.random.randint(255)
            new_secret_image.putpixel((x, y), (color1, color2, color3))
            new_secret_image.putpixel((x + 1, y), (255 - color1, 255 - color2, 255 - color3))
            new_secret_image.putpixel((x, y + 1), (255 - color1, 255 - color2, 255 - color3))
            new_secret_image.putpixel((x + 1, y + 1), (color1, color2, color3))
                
    return new_secret_image

def generate_ciphered_image(secret_image, prepared_image):
    width, height = prepared_image.size
    ciphered_image = Image.new(mode="RGB", size=(width * 2, height * 2))
    for x in range(0, width * 2, 2):
        for y in range(0, height * 2, 2):
            sec = secret_image.getpixel((x, y))
            msssg = prepared_image.getpixel((int(x / 2), int(y / 2)))
            color1 = (msssg[0] + sec[0]) % 256
            color2 = (msssg[1] + sec[1]) % 256
            color3 = (msssg[2] + sec[2]) % 256
            ciphered_image.putpixel((x, y), (color1, color2, color3))
            ciphered_image.putpixel((x + 1, y), (255 - color1, 255 - color2, 255 - color3))
            ciphered_image.putpixel((x, y + 1), (255 - color1, 255 - color2, 255 - color3))
            ciphered_image.putpixel((x + 1, y + 1), (color1, color2, color3))
                
    return ciphered_image

def generate_image_back(secret_image, ciphered_image):
    width, height = secret_image.size
    new_image = Image.new(mode="RGB", size=(int(width / 2), int(height / 2)))
    for x in range(0, width, 2):
        for y in range(0, height, 2):
            sec = secret_image.getpixel((x, y))
            cip = ciphered_image.getpixel((x, y))
            color1 = (cip[0] - sec[0]) % 256
            color2 = (cip[1] - sec[1]) % 256
            color3 = (cip[2] - sec[2]) % 256
            new_image.putpixel((int(x / 2), int(y / 2)), (color1, color2, color3))
               
    return new_image

#------------------------Encryption -------------------#
def level_one_encrypt(Imagename):
    message_image = load_image(Imagename)
    size = message_image.size
    width, height = size

    secret_image = generate_secret(size)
    secret_image.save("secret.jpeg")

    prepared_image = prepare_message_image(message_image, size)
    ciphered_image = generate_ciphered_image(secret_image, prepared_image)
    ciphered_image.save("2-share_encrypt.jpeg")

# -------------------- Construct Encrypted Image  ----------------#
def construct_enc_image(ciphertext, relength, width, height):
    asciicipher = binascii.hexlify(ciphertext)
    def replace_all(text, dic):
        for i, j in dic.items():
            text = text.replace(i, j)
        return text

    # use replace function to replace ascii cipher characters with numbers
    reps = {chr(i): str(i - 96) for i in range(97, 123)}  # 'a' to 'z'
    asciiciphertxt = replace_all(asciicipher.decode(), reps)

    # construct encrypted image
    step = 3
    encimageone = [asciiciphertxt[i:i + step] for i in range(0, len(asciiciphertxt), step)]
    # if the last pixel RGB value is less than 3-digits, add a digit of 1
    if int(encimageone[-1]) < 100:
        encimageone[-1] += "1"
    # check to see if we can divide the string into partitions of 3 digits. if not, fill in with some garbage RGB values
    if len(encimageone) % 3 != 0:
        while len(encimageone) % 3 != 0:
            encimageone.append("101")

    encimagetwo = [(int(encimageone[int(i)]), int(encimageone[int(i + 1)]), int(encimageone[int(i + 2)])) for i in range(0, len(encimageone), step)]
    while int(relength) != len(encimagetwo):
        encimagetwo.pop()

    encim = Image.new("RGB", (int(width), int(height)))
    encim.putdata(encimagetwo)
    encim.save("visual_encrypt.jpeg")

#------------------------- Visual-encryption -------------------------#
def encrypt(imagename, password):
    plaintext = []
    plaintextstr = ""

    im = Image.open(imagename) 
    pix = im.load()

    width = im.size[0]
    height = im.size[1]
    
    # break up the image into a list, each with pixel values and then append to a string
    for y in range(height):
        for x in range(width):
            plaintext.append(pix[x, y])

    # add 100 to each tuple value to make sure each are 3 digits long.  
    for i in range(len(plaintext)):
        for j in range(3):
            aa = int(plaintext[i][j]) + 100
            plaintextstr += str(aa)

    # length save for encrypted image reconstruction
    relength = len(plaintext)

    # append dimensions of image for reconstruction after decryption
    plaintextstr += "h" + str(height) + "h" + "w" + str(width) + "w"

    # make sure that plaintextstr length is a multiple of 16 for AES. if not, append "n". 
    while len(plaintextstr) % 16 != 0:
        plaintextstr += "n"

    # encrypt plaintext
    obj = AES.new(password, AES.MODE_CBC, b'This is an IV456')
    ciphertext = obj.encrypt(plaintextstr.encode())

    # write ciphertext to file for analysis
    cipher_name = imagename + ".crypt"
    with open(cipher_name, 'wb') as g:
        g.write(ciphertext)
    construct_enc_image(ciphertext, relength, width, height)
    level_one_encrypt("visual_encrypt.jpeg")

    # Call the encryption success message
    enc_success("visual_encrypt.jpeg")

# ---------------------- decryption ---------------------- #
def decrypt(ciphername, password):
    secret_image = Image.open("secret.jpeg")
    ima = Image.open("2-share_encrypt.jpeg")
    new_image = generate_image_back(secret_image, ima)
    new_image.save("2-share_decrypt.jpeg")

    cipher = open(ciphername, 'rb')
    ciphertext = cipher.read()

    # decrypt ciphertext with password
    obj2 = AES.new(password, AES.MODE_CBC, b'This is an IV456')
    decrypted = obj2.decrypt(ciphertext)

    # parse the decrypted text back into integer string
    decrypted = decrypted.decode().replace("n", "")

    # extract dimensions of images
    newwidth = decrypted.split("w")[1]
    newheight = decrypted.split("h")[1]

    # replace height and width with empty space in decrypted plaintext
    heightr = "h" + str(newheight) + "h"
    widthr = "w" + str(newwidth) + "w"
    decrypted = decrypted.replace(heightr, "")
    decrypted = decrypted.replace(widthr, "")

    # reconstruct the list of RGB tuples from the decrypted plaintext
    step = 3
    finaltextone = [decrypted[i:i + step] for i in range(0, len(decrypted), step)]
    finaltexttwo = [(int(finaltextone[int(i)]) - 100, int(finaltextone[int(i + 1)]) - 100, int(finaltextone[int(i + 2)]) - 100) for i in range(0, len(finaltextone), step)]

    # reconstruct image from list of pixel RGB tuples
    newim = Image.new("RGB", (int(newwidth), int(newheight)))
    newim.putdata(finaltexttwo)
    newim.save("visual_decrypt.jpeg")

    # Call the decryption success message
    dec_success()

# New function for encryption success message
def enc_success(imagename):
    messagebox.showinfo("Success", "Encrypted Image: " + imagename)

# New function for decryption success message
def dec_success():
    messagebox.showinfo("Success", "Decryption Successful!")

# --------------------- GUI stuff starts here ---------------------#

def pass_alert():
    messagebox.showinfo("Password Alert", "Please enter a password.")

# image encrypt button event
def image_open():
    global file_path_e

    enc_pass = passg.get()
    if enc_pass == "":
        pass_alert()
    else:
        password = hashlib.sha256(enc_pass.encode()).digest()  # Encode before hashing
        filename = filedialog.askopenfilename()
        file_path_e = os.path.dirname(filename)
        encrypt(filename, password)

# image decrypt button event
def cipher_open():
    global file_path_d

    dec_pass = passg.get()
    if dec_pass == "":
        pass_alert()
    else:
        password = hashlib.sha256(dec_pass.encode()).digest()  # Encode before hashing
        filename = filedialog.askopenfilename()
        file_path_d = os.path.dirname(filename)
        decrypt(filename, password)

class App:
    def __init__(self, master):
        global passg
        title = "IMAGE ENCRYPTION AND DECRYPTION"
        author = "Made by KRISHPATEL"
        msgtitle = Message(master, text=title)
        msgtitle.config(font=('helvetica', 17, 'bold'), width=200)
        msgauthor = Message(master, text=author)
        msgauthor.config(font=('helvetica', 10), width=200)

        canvas_width = 200
        canvas_height = 50
        w = Canvas(master, width=canvas_width, height=canvas_height)
        msgtitle.pack()
        msgauthor.pack()
        w.pack()

        passlabel = Label(master, text="Enter Encrypt/Decrypt Password:")
        passlabel.pack()
        passg = Entry(master, show="*", width=20)
        passg.pack()

        self.encrypt = Button(master, text="Encrypt", fg="black", command=image_open, width=25, height=5)
        self.encrypt.pack(side=LEFT)
        self.decrypt = Button(master, text="Decrypt", fg="black", command=cipher_open, width=25, height=5)
        self.decrypt.pack(side=RIGHT)

# ------------------ MAIN -------------#
root = Tk()
root.wm_title("Image Encryption")
app = App(root)
root.mainloop()