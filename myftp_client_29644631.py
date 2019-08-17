#!/usr/bin/env python3
import os
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import *
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding as pad
from cryptography.exceptions import InvalidSignature
from cryptography.exceptions import AlreadyFinalized
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa


import binascii as ba
import socket

class bcolors:
    Purple = '\033[1;35;40m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    succ = '\033[1;32;40m'
    Blue = '\033[1;34;40m'


def writeBuffer(request):
    return b'length:' + bytes(str(len(request)),'utf-8') + b'content:' + request


def ReadBuffer(sock):

    message = sock.recv(1024).strip()
    if b'length:' in message:
        length = (message.split(b'length:'))[1].split(b'content:')[0]

        if int(length,10) > 1024:
            newmessage = sock.recv(int(length)).strip()
            message = message + newmessage

        if b'content:' in message:
            content = message.split(b'content:',1)[1]

            return content

        else:
            return False
    else:
        return False


def UserMenu(content):

    KeyExch=AuthAlg=BlukEnc=hashAlg=""
    content = str(content).strip('\'').split()
    content = list(content)
    finalRespon = "Agree On! "

    j=0
    while j < len(content):
        prpose = content[j].split(":")
        if content[j] not in prpose:
            option = prpose[1].split(",")
            option =  list(option)
            x = 1
            print("Proposed",prpose[0])
            for n in range(len(option)):
              print("[",x,"]",option[n])
              x+=1

            selection = input("Type the choose as it appear:")
            respon= prpose[0]+":"+selection
            finalRespon = finalRespon + respon + " "

            if "Key_Exchange" in prpose[0]:
                KeyExch = selection
            elif "Authentication_Algorithms" in prpose[0]:
                AuthAlg = selection
            elif "Bulk_Encryption" in prpose[0]:
                BlukEnc = selection
            elif "Hash" in prpose[0]:
                hashAlg = selection

        j+=1
    return bytes(finalRespon,'utf-8'),KeyExch, AuthAlg, BlukEnc, hashAlg



def loadServerAndCACert():

    try:
        with open('./ClientCert.pem', 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
            f.close()

        with open('./MyRootCA.pem', 'rb') as f:
            CAcert = x509.load_pem_x509_certificate(f.read(), default_backend())
            issuer_public_key = CAcert.public_key()
            f.close()
        return cert, issuer_public_key
    except IOError:
        print(bcolors.FAIL + "file could not be opened"+bcolors.ENDC)
        return False




def Auth_Serer_Cert(issuer_public_key,serverCert):
    try:
        issuer_public_key.verify(
        serverCert.signature,
        serverCert.tbs_certificate_bytes,
        # Depends on the algorithm used to create the certificate
        pad.PKCS1v15(),
        serverCert.signature_hash_algorithm,
        )
        print(bcolors.succ + "Server Certificate validated successfully...." + bcolors.ENDC)
        return True

    except InvalidSignature:
        print(bcolors.FAIL +"Invalid Certificate..."+bcolors.ENDC)
        return False


def GenerateAsymmKey(BlukEnc,iv,key):

    if BlukEnc == "AES-256-CBC":
        BlukEnc = modes.CBC(iv)
    else:
        BlukEnc = modes.OFB(iv)

    cipher = Cipher(algorithms.AES(key), BlukEnc, default_backend())
    print(bcolors.succ+"Symmetric key has been generated successfully..."+bcolors.ENDC)
    return cipher



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
    print(bcolors.succ+"Symmetric key has been generated successfully..."+bcolors.ENDC)
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


def GetServerPubKey(serverCert):
    server_pub_key = serverCert.public_key()
    check = isinstance(server_pub_key, rsa.RSAPublicKey)
    if check:
        print(bcolors.succ+"Server public RSA key has been obtained successfully..."+bcolors.ENDC)
        return server_pub_key
    else:
        print(bcolors.FAIL+"Server RSA public key couldn't be obtained..."+bcolors.ENDC)
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
                print(bcolors.succ+"Client Private RSA  key has been obtained successfully..."+bcolors.ENDC)
                return private_key
            else:
                print(bcolors.FAIL+"Server RSA public key couldn't be obtained..."+bcolors.ENDC)
                return False

    except IOError:
        print(bcolors.FAIL+"file could not be opened"+bcolors.ENDC)


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
    print(bcolors.succ + "Message has been signed successfully...." + bcolors.ENDC)
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

        print(bcolors.succ + "Signature has been verified successfully" + bcolors.ENDC)
        return True
    except InvalidSignature:
        print(bcolors.FAIL + "invalidSignature" + bcolors.ENDC)
        return False


def RSADecrypt(private_key,ciphertext):
    plaintext = private_key.decrypt(
    ciphertext,
        pad.OAEP(
        mgf=pad.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        )
    )
    print(bcolors.succ + "Symmetric key has been decrypted using private key successfully...." + bcolors.ENDC)
    return plaintext



def displayFileListing(cwdList):

    #convert list to dictionay
    dirList = cwdList.split("+.+.+")

    #generate key list
    keyList = list(x for x in range(1,len(dirList)+1))

    #generate dictionary
    dirDict = dict((key, value) for (key, value) in zip(keyList, dirList))

    #print file list
    print('{:<10s}{:<40s}{:<20s}'.format('Option','Name','Size'))
    for key, value in dirDict.items():
        print('{:<10d}{:<40s}{:<20s}'.format(key, value.split(" ")[0], value.split(" ")[1]))

    #select option of file to be transfered
    option = int(input("Select option of file to be selected: "))

    return option, dirDict


def main():


    host=(input("Enter server IP address or FQDN [10.11.1.10]: \n") or "10.11.1.10")
    port=(input("Enter the server port number [7777]: \n") or 7777)


    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port = int(port)

    print(bcolors.succ+ "You are connecting to Server: ",host, "and port", port ,bcolors.ENDC, "\n\n")
    sock.connect((host, port))
    # prepare the hash of all communication
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    request = b'Hello'


    sock.sendall(writeBuffer(request))
    outgoing = request.strip() + b' '



    received = ReadBuffer(sock)
    incoming = received

    if b'Hey there!' in received:

        request, KeyExch, AuthAlg, BlukEnc, hashAlg= UserMenu(received)

        sock.sendall(writeBuffer(request))
        outgoing = outgoing + request.strip() + b' '


    else:

        print(bcolors.FAIL+'Bad response'+bcolors.ENDC)

        sock.close()
        return


    received = ReadBuffer(sock)
    incoming = incoming + received

    if b'Hey there!' in received:
        print(bcolors.WARNING+"Server re-negotiate...."+bcolors.ENDC)
        request, KeyExch, AuthAlg, BlukEnc, hashAlg= UserMenu(received)
        sock.sendall(writeBuffer(request))
        outgoing = outgoing + request.strip() + b' '
        received = ReadBuffer(sock)
        incoming = incoming + received

        if b'I do not understand you, hanging up' in received:
            print(bcolors.FAIL+'Bad response'+bcolors.ENDC)
            sock.close()
            return


    print(bcolors.succ + "Negotiation has been done successfully.... "+bcolors.ENDC)
    # recive cert and check and replay with its cert
    cert, issuer_public_key = loadServerAndCACert()
    serverCert = x509.load_pem_x509_certificate(bytes(bytearray(received)), default_backend())
    cert_check = Auth_Serer_Cert(issuer_public_key,serverCert)

    if cert_check:

        sock.sendall(writeBuffer(cert.public_bytes(Encoding.PEM)))
        outgoing = outgoing + cert.public_bytes(Encoding.PEM).strip() + b' '

    else:
        print(bcolors.FAIL+'Bad response'+bcolors.ENDC)
        sock.close()
        return




    if KeyExch == "DHE":
        print(bcolors.Purple + "Start DHE Key Exchange..." + bcolors.ENDC)
        received = ReadBuffer(sock)
        incoming = incoming + received
        dh_params = load_pem_parameters(received, default_backend())
        if isinstance(dh_params, dh.DHParameters):
            client_keypair = dh_params.generate_private_key()
            print(bcolors.Purple+"Generating DHE public key... "+bcolors.ENDC)
            request = b'Client public key:' + client_keypair.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            sock.sendall(writeBuffer(request))
            outgoing = outgoing + request.strip() + b' '
            print(bcolors.succ+"DHE generated successfully....."+bcolors.ENDC)
            received = ReadBuffer(sock)
            incoming = incoming + received

            if bytearray(received)[0:18] == b'Server public key:':
                server_pubkey = load_pem_public_key(bytes(bytearray(received)[18:]), default_backend())
                print(bcolors.Purple+"Verify server DHE public key..."+bcolors.ENDC)
                if isinstance(server_pubkey, dh.DHPublicKey):

                    shared_secret = client_keypair.exchange(server_pubkey)
                    print(bcolors.succ+"Shared Secrete has been generated successfully...."+bcolors.ENDC)
                    #print("share sec:",shared_secret)
                    print(bcolors.Purple+"Derive Symmetric key..."+bcolors.ENDC)
                    cipher = deriveKey(shared_secret,hashAlg,BlukEnc)

                else:
                    print(bcolors.FAIL+'Bad response'+bcolors.ENDC)
                    sock.close()
                    return
            else:
                print(bcolors.FAIL+'Bad response'+bcolors.ENDC)
                sock.close()
                return



        else:
            print(bcolors.FAIL+'Bad response'+bcolors.ENDC)
            sock.close()
            return


    elif KeyExch == "RSA":
        print(bcolors.Purple + "Start RSA Key Exchange..." + bcolors.ENDC)
        received = ReadBuffer(sock)
        incoming = incoming + received

        rsa_private_key = Load_Private_key()
        plaintext = RSADecrypt(rsa_private_key,received)


        if bytearray(plaintext)[0:3] == b'iv:':
            iv = (plaintext.split(b'iv:'))[1].split(b'key:')[0]
            key = plaintext.split(b'key:',1)[1]

            cipher = GenerateAsymmKey(BlukEnc,iv,key)

        else:
            print(bcolors.FAIL+'Bad response'+bcolors.ENDC)
            sock.close()
            return


    else:
        print(bcolors.FAIL+'Bad response'+bcolors.ENDC)
        sock.close()
        return


# Authanticate the server
    server_RSA_pubkey = GetServerPubKey(serverCert)
    rsa_private_key = Load_Private_key()

    digest.update(outgoing)
    digest.update(incoming)
    hashCom = digest.finalize()

    signature = Signing_Data(rsa_private_key,hashCom,hashAlg)

    sock.sendall(writeBuffer(b'Client signature:' + signature + b' client Hash:' + hashCom))

    received = ReadBuffer(sock)
   

    if bytearray(received)[0:17] == b'Server signature:':
            clientSignature = (received.split(b'Server signature:'))[1].split(b' Server Hash:')[0]
            serverHash = received.split(b' Server Hash:',1)[1]
    else:
        print(bcolors.FAIL+'Bad response'+bcolors.ENDC)
        sock.close()
        return

    if hashCom == serverHash:
        check_cert = Verification(server_RSA_pubkey,clientSignature,serverHash,hashAlg)

        if check_cert:
############## start of secure communication ##############
            print(bcolors.Blue + "Start of secure channel" + bcolors.ENDC)
            message = b"Ready For list of files!"
            request = Encrypt(cipher,message)
            sock.sendall(writeBuffer(request))

            # recive list
            received = ReadBuffer(sock)
            decMessage = Decrypt(cipher,received)

            #display list of files
            selection, dirDict = displayFileListing(str(decMessage))


            #convert string to binary and send
            reqFile = dirDict.get(selection).split(" ")[0].encode('utf-8')
            print("file requested:",reqFile,"\n")

            request = Encrypt(cipher,reqFile)
            sock.sendall(writeBuffer(request))

            # recive file
            received = ReadBuffer(sock)
            decMessage = Decrypt(cipher,received)
            print("this is the file:\n",decMessage)

            if decMessage != b'File Does not exist':
                print(bcolors.Purple + "Reciveing",dirDict.get(selection).split(" ")[0]," of size ",dirDict.get(selection).split(" ")[1]," bytes" + bcolors.ENDC)

                print("transBin",decMessage)
                with open(dirDict.get(selection).split(" ")[0], 'wb') as f:
                    f.write(decMessage)
                    f.close()
                print(bcolors.succ + "File ",dirDict.get(selection).split(" ")[0], "has been received successfully" + bcolors.ENDC)



        else:
            print(bcolors.FAIL+'Server Untrusted'+bcolors.ENDC)
            sock.close()
            return
    else:
        print(bcolors.FAIL+'Server Unknown'+bcolors.ENDC)
        sock.close()
        return







    sock.close()
    return
if __name__ == '__main__':
    main()
