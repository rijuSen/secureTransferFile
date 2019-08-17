#!/usr/bin/env python3
import os
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import *
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding as pad
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from os.path import join, getsize
import socketserver
import sys


def writeBuffer(request):
    return b'length:' + bytes(str(len(request)),'utf-8') + b'content:' + request

def ReadBuffer(request):

    message = request.recv(1024).strip()
    if b'length:' in message:
        length = (message.split(b'length:'))[1].split(b'content:')[0]

        if int(length,10) > 1024:
            newmessage = request.recv(int(length)).strip()
            message = message + newmessage
        if b'content:' in message:
            content = message.split(b'content:',1)[1]
            return content

        else:
            return False
    else:
        return False

def DecodeClientChoose(message):


    message = str(message).strip('\'').split()
    message = list(message)
    j = 0
    while j < len(message):
        if "Key_Exchange" in message[j]:
            option = message[j].split(":")
            KeyExch = option[1]
        elif "Authentication_Algorithms" in message[j]:
            option = message[j].split(":")
            AuthAlg = option[1]
        elif "Bulk_Encryption" in message[j]:
            option = message[j].split(":")
            BlukEnc = option[1]
        elif "Hash" in message[j]:
            option = message[j].split(":")
            hashAlg = option[1]

        j+=1
    print("OPtion: ",KeyExch,AuthAlg,BlukEnc,hashAlg)
    return CheckClientChoice(KeyExch,AuthAlg,BlukEnc,hashAlg)


def CheckClientChoice(KeyExch,AuthAlg,BlukEnc,hashAlg):

    if KeyExch == "RSA":
        print("KEY EXCH = RSA")
        checkKey = True
    elif KeyExch == "DHE":
        print("KEY EXCH = DHE")
        checkKey = True
    else:
        print("KEY EXCH = not supported")
        checkKey = False


    if hashAlg == "sha256":
        print("hash Alg = sha256")
        checkHash = True
    elif hashAlg == "sha384":
        print("hashAlg = sha384")
        checkHash = True
    else:
        print("hashAlg= not supported")
        checkHash = False


    if AuthAlg == "RSA":
        print("Auth Alg = RSA")
        checkAuth = True
    else:
        print("Auth Alg = not supported")
        checkAuth = False


    if BlukEnc == "AES-256-CBC":
        print("Bulk Encryption = AES-256-CBC")
        checkEnc= True
    elif BlukEnc == "AES-256-OFB":
        print("Bulk Encryption = AES-256-OFBC")
        checkEnc = True
    else:
        print("Bulk_Encryption = not supported")
        checkEnc = False

    if checkKey & checkHash & checkAuth & checkEnc:
        return True,KeyExch, AuthAlg, BlukEnc, hashAlg
    else:
        print("\nRe-negotiate!!.....")
        return False,KeyExch, AuthAlg, BlukEnc, hashAlg

def loadServerAndCACert():

    try:
        with open('./ServerCert.pem', 'rb') as r:
            cert = x509.load_pem_x509_certificate(r.read(), default_backend())
            #cert = f.readable()
            r.close()

        with open('./MyRootCA.pem', 'rb') as f:
            CAcert = x509.load_pem_x509_certificate(f.read(), default_backend())
            issuer_public_key = CAcert.public_key()
            f.close()
        return cert, issuer_public_key
    except IOError:
        print("file could not be opened")
        return False





def load_dh_params():

    with open('./dh_2048_params.bin', 'rb') as f:

        params = load_pem_parameters(f.read(), default_backend())

    print('Parameters have been read from file, Server is ready for requests ...')
    return params


def generate_dh_prvkey(params):


    return params.generate_private_key()



def check_client_pubkey(pubkey):

    if isinstance(pubkey, dh.DHPublicKey):
        return True
    else:
        return False


def Auth_Client_Cert(issuer_public_key,clientCert):
    try:
        issuer_public_key.verify(
        clientCert.signature,
        clientCert.tbs_certificate_bytes,
        # Depends on the algorithm used to create the certificate
        pad.PKCS1v15(),
        clientCert.signature_hash_algorithm,
        )
        print("Client Certificate validated successfully....")
        return True

    except InvalidSignature:
        print("Invalid Certificate \n\n")
        return False

def GenerateAsymmKey(BlukEnc):

    iv = os.urandom(16)
    key = os.urandom(32)

    if BlukEnc == "AES-256-CBC":
        BlukEnc = modes.CBC(iv)
    else:
        BlukEnc = modes.OFB(iv)

    cipher = Cipher(algorithms.AES(key), BlukEnc, default_backend())

    return iv, key, cipher




def deriveKey(shared_secret,hashAlg,BlukEnc):

    if hashAlg == "sha256":
        hashAlg = hashes.SHA256()

    else:
         hashAlg = hashes.SHA3_384()

    salt = bytes(bytearray(shared_secret)[0:16])
    key = HKDF(
        algorithm=hashAlg,
        length=24,
        salt=salt,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_secret)

    iv = bytearray(shared_secret)[0:16]

    if BlukEnc == "AES-256-CBC":
        BlukEnc = modes.CBC(iv)
    else:
        BlukEnc = modes.OFB(iv)

    cipher = Cipher(algorithms.AES(key), BlukEnc, default_backend())
    print("Symmetric key has been generated successfully...")
    return cipher


def Encrypt(cipher,message):

    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message)
    padded_data += padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()



def Decrypt(cipher,message):

    decryptor = cipher.decryptor()
    dec = decryptor.update(message) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(dec)
    return data + unpadder.finalize()


def GetClientPubKey(serverCert):
    server_pub_key = serverCert.public_key()
    check = isinstance(server_pub_key, rsa.RSAPublicKey)
    if check:
        print("Server public RSA key has been obtained successfully...")
        return server_pub_key
    else:
        print("Server RSA public key couldn't be obtained...")
        return False

def Load_Private_key():

    try:
        with open('./rsaPrivate.key', 'rb') as r:
            private_key = serialization.load_pem_private_key(
            r.read(),
            password=None,
            backend=default_backend()
            )
            check = isinstance(private_key, rsa.RSAPrivateKey)
            r.close()
            if check:
                print("Client Private RSA  key has been obtained successfully...")
                return private_key
            else:
                print("Server RSA public key couldn't be obtained...")
                return False

    except IOError:
        print("file could not be opened")


def Signing_Data(private_key,message,hashAlg):

    if hashAlg == "sha256":
        hashAlg = hashes.SHA256()

    else:
         hashAlg = hashes.SHA3_384()

    signature = private_key.sign(
        message,
        pad.PSS(
        mgf=pad.MGF1(hashAlg),
        salt_length=pad.PSS.MAX_LENGTH
        ),
        hashAlg
    )
    print("Message has been signed successfully....")
    return signature



def Verification(client_pub_key,signature,message,hashAlg):

    try:

        if hashAlg == "sha256":
            hashAlg = hashes.SHA256()

        else:
            hashAlg = hashes.SHA3_384()

        client_pub_key.verify(
        signature,
        message,
        pad.PSS(
            mgf=pad.MGF1(hashAlg),
            salt_length=pad.PSS.MAX_LENGTH
            ),
        hashAlg
        )

        print("Signature has been verified successfully")
        return True
    except InvalidSignature:
        print("invalidSignature")
        return False


def RSAEncrypt(client_RSA_pubkey,message):

    ciphertext = client_RSA_pubkey.encrypt(
        message,
        pad.OAEP(
        mgf=pad.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
         )
    )

    return ciphertext


def getFileListing():
    #file transfer
    #sending directory list
    dirList = list()
    cwd = os.getcwd()
    for root, dirs, files in os.walk(cwd, topdown=True):
        del dirs[:]  # remove the sub directories.
        for file in files:
            dirList.append((file+" "+str(getsize(join(root, file)))))

    dirListString = '+.+.+'.join(dirList)
    print(dirListString)
    dirListBin = bytes(dirListString,'utf-8')
    return dirList, dirListBin



class Dh_Handler(socketserver.BaseRequestHandler):


    def __init__(self, request, client_address, server):
        self.params = load_dh_params()
        self.state = 0
        socketserver.BaseRequestHandler.__init__(self, request, client_address, server)



    def handle(self):
        # prepare the hash of all communication
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        self.data = ReadBuffer(self.request)
        incoming = self.data + b' '


        if self.state == 0 and self.data == b'Hello':

            self.state = 1

            print(self.data, self.state)
            trytime = 0
            outgoing = b''
            while  trytime < 2:
                response = b'Hey there!, Key_Exchange:RSA,DHE Authentication_Algorithms:RSA Bulk_Encryption:AES-256-CBC,AES-256-OFB Hash:sha256,sha384'
                self.request.sendall(writeBuffer(response))
                outgoing = outgoing + response.strip()
                self.data = ReadBuffer(self.request)
                incoming = incoming + self.data + b' '

                if self.state == 1 and b'Agree On!' in self.data:
                    self.state = 2
                    check,KeyExch, AuthAlg, BlukEnc, hashAlg= DecodeClientChoose(self.data)
                    if check:
                        print("Negotiation has been done successfully.... ")
                        # send server certificate and ask for client
                        cert, issuer_public_key = loadServerAndCACert()
                        self.request.sendall(writeBuffer(cert.public_bytes(Encoding.PEM)))
                        outgoing = outgoing + cert.public_bytes(Encoding.PEM).strip()
                        self.data = ReadBuffer(self.request)
                        incoming = incoming + self.data + b' '
                        clientCert = x509.load_pem_x509_certificate(bytes(bytearray(self.data)), default_backend())
                        cert_check = Auth_Client_Cert(issuer_public_key,clientCert)

                        if cert_check == False:
                            response = b'I do not understand you, hanging up'
                            self.request.sendall(writeBuffer(response))
                            return
                        break

                    else:
                        self.state = 1
                        trytime+=1

                else:
                    trytime+=1

                if trytime == 2:
                    response = b'I do not understand you, hanging up'
                    self.request.sendall(writeBuffer(response))
                    return


        else:
            response = b'I do not understand you, hanging up'
            self.request.sendall(writeBuffer(response))
            return


        if KeyExch == "DHE":

            dh_params = self.params
            response = dh_params.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3)
            self.request.sendall(writeBuffer(response))
            outgoing = outgoing + response.strip()

            self.data = ReadBuffer(self.request)
            incoming = incoming + self.data + b' '
            print("verify client DHE public key....")
            if self.state == 2 and bytearray(self.data)[0:18] == b'Client public key:':
                client_pubkey = load_pem_public_key(bytes(bytearray(self.data)[18:]), default_backend())

                if client_pubkey:
                    server_keypair = generate_dh_prvkey(self.params)
                    print("Generate DHE public key...")
                    response = b'Server public key:' + server_keypair.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                    self.request.sendall(writeBuffer(response))
                    outgoing = outgoing + response.strip()
                    print("DHE generated successfully.....")

                    shared_secret = server_keypair.exchange(client_pubkey)
                    print("Shared Secrete has been generated successfully....")
                    print("Derive Symmetric key...")
                    cipher = deriveKey(shared_secret,hashAlg,BlukEnc)


                else:
                    response = b'Invalid client public key, hanging up'
                    self.request.sendall(writeBuffer(response))
                    return


        elif KeyExch == "RSA":

            iv, key, cipher = GenerateAsymmKey(BlukEnc)
            client_RSA_pubkey = GetClientPubKey(clientCert)
            ciphertext = RSAEncrypt(client_RSA_pubkey,b'iv:' + iv + b'key:' + key)

            self.request.sendall(writeBuffer(ciphertext))
            outgoing = outgoing + ciphertext.strip()


######## Authenticate the server ##########

        digest.update(incoming)
        digest.update(outgoing)
        hashCom = digest.finalize()

        self.data = ReadBuffer(self.request)


        if bytearray(self.data)[0:17] == b'Client signature:':
            clientSignature = (self.data.split(b'Client signature:'))[1].split(b' client Hash:')[0]
            clientHash = self.data.split(b' client Hash:',1)[1]
        else:
            response = b'Invalid respon, hanging up'
            self.request.sendall(writeBuffer(response))
            return

        if hashCom == clientHash:
            client_RSA_pubkey = GetClientPubKey(clientCert)
            rsa_private_key = Load_Private_key()
            check_cert = Verification(client_RSA_pubkey,clientSignature,clientHash,hashAlg)

            if check_cert:
                signature = Signing_Data(rsa_private_key,hashCom,hashAlg)
                self.request.sendall(writeBuffer(b'Server signature:' + signature + b' Server Hash:' + hashCom))

            else:
                response = b'I do not TRUST YOU!'
                self.request.sendall(writeBuffer(response))
        else:
            response = b'I do not know you!'
            self.request.sendall(writeBuffer(response))

############## start of secure communication ##############

        self.data = ReadBuffer(self.request)
        decMessage = Decrypt(cipher,self.data)

        if decMessage == b"Ready For list of files!":

            # send a list of files
            cwdList, cwdListBin = getFileListing()
            print("cwdListBin:",cwdListBin)
            print("cwdList:",cwdList)
            response = Encrypt(cipher,cwdListBin)
            response = bytes(bytearray(response))
            self.request.sendall(writeBuffer(response))

            # receive client file request
            self.data = ReadBuffer(self.request)
            decMessage = Decrypt(cipher,self.data)

            #convert binary data into str
            fileReqStr = decMessage.decode('utf-8')
            #remove size value from list
            dirListNames = list(x.split(" ")[0] for x in cwdList)

            #check if the file is present
            if fileReqStr in dirListNames:

                with open(fileReqStr, 'rb') as f:
                    reqFileTrans = f.read()
                #send the binary data to client
                response = Encrypt(cipher,reqFileTrans)
                self.request.sendall(writeBuffer(response))

            else:
                response = Encrypt(cipher,b'File Does not exist')
                print("encrypted message:",response)
                self.request.sendall(writeBuffer(response))






def main():

    host, port = '', 7777

    dh_server = socketserver.TCPServer((host, port), Dh_Handler)

    try:
        print("the server is listening on port 7777")
        dh_server.serve_forever()

    except KeyboardInterrupt:
        dh_server.shutdown()
        sys.exit(0)
if __name__ == '__main__': main()

