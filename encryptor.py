import os
from Crypto import Random
from Crypto.Cipher import AES
from Tkinter import *
import hashlib
import tkMessageBox
class Start():
    def __init__(self):
        self.key = b"\x54\xEF\x41\xFF\xBF\xDD\xD5\xC2\xF6\xC1\xF6\xDF\xFF\xD5\x9E\xB4\x9C\x1F\x86\xD4\xC2\xE3\xC6\x8A\x34\x99\x3E\xCF\x20\x33\x7E\xCA"

        self.root = Tk()
        self.root.geometry("300x300")
        self.leb = Label(self.root, text="username:")
        self.leb.place(x=50,y=40)
        self.eny1 = Entry(self.root)
        self.eny1.place(x=120,y=40)
        self.leb = Label(self.root, text="password:")
        self.leb.place(x=50, y=100)
        self.eny = Entry(self.root, show="*")
        self.eny.place(x=120, y=100)
        self.butt = Button(self.root, text="encrypt", command=self.chechklogin1)
        self.butt.place(x=100,y=200)
        self.butt = Button(self.root, text="decrypt",command=self.chechklogin2)
        self.butt.place(x=200, y=200)

        mainloop()

    def chechklogin2(self):
        username = self.eny1.get()
        passowrd =self.eny.get()
        md5 = hashlib.sha512()
        md5.update(passowrd)
        a=md5.hexdigest()
        print a
        if username == "michael-lev":
            if a == "34e1fd6820ce1e79fbbdaae3fc708b634ab1d9765c215b7cd88d4c0c750e87b8c1d478b6112d95ae7bd165f9f73d165263ef7fcee357b48c6bc1f6b591f94ab8":
                print "hello"
                self.openfile(self.key)
            else:
                print "sorry"

        else:
            tkMessageBox._show("sorry ","error password or username")


    def chechklogin1(self):
        username = self.eny1.get()
        passowrd =self.eny.get()
        md5 = hashlib.sha512()
        md5.update(passowrd)
        a=md5.hexdigest()
        print a
        if username == "michael-lev":
            if a == "34e1fd6820ce1e79fbbdaae3fc708b634ab1d9765c215b7cd88d4c0c750e87b8c1d478b6112d95ae7bd165f9f73d165263ef7fcee357b48c6bc1f6b591f94ab8":
                print "hello"
                self.colose(self.key)
            else:
                print "sorry"
        else:
            tkMessageBox._show("sorry ","error password or username")


    def openfile(self,key):
        dirctory = os.listdir("hidden-files")
        os.chdir("hidden-files")
        for f in dirctory:
            print f, dirctory
            with open(str(f), 'rb')as g:
                readdata = g.read()
            print readdata
            g.close()
            aa = self.derypt(readdata, key)
            for hh, dirctory in enumerate(dirctory):
                with open(str(dirctory), 'wb')as v:
                    v.write(aa)
                v.close()






    def colose(self,key):
        dirctory = os.listdir("hidden-files")
        os.chdir("hidden-files")
        for f in dirctory:
            print f, dirctory
            with open(str(f), 'rb')as g:
                readdata = g.read()
            print readdata
            g.close()
            aa = self.encrypt(readdata, key)
            for hh, dirctory in enumerate(dirctory):
                with open(str(dirctory), 'wb')as v:
                    v.write(aa)
                v.close()


    def pad(self,s):
        return s +b"\0" *(AES.block_size - len(s) % AES.block_size)

    def encrypt(self,mag,key,key_size=8060):
        mag = self.pad(mag)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key,AES.MODE_CBC,iv)
        return iv + cipher.encrypt(mag)


    def derypt(self,ciphertext,key):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key,AES.MODE_CBC,iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")


f = Start()

def main():
    f
main()

