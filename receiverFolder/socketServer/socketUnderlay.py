#!/usr/bin/env python3

class SocketUnderlay:
    def __init__(self, host):
        import socket
        self.host = host
        self.port = 7777
        self.s = socket.socket()
        self.s.connect((self.host,self.port))

    def sendData(self,binData):
        self.s.send(binData)

    def recvData(self,dataSize):
        recvData = self.s.recv(dataSize)
        return recvData

    def closeConn(self):
        self.s.close()
