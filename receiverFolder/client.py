#!/usr/bin/env python3


from socketServer.socketUnderlay import SocketUnderlay

def displayFileListing(cwdList):
    dirList = cwdList.split("+.+.+")
    
    #convert list to dictionay
    
    #generate key list
    keyList = list(x for x in range(1,len(dirList)+1))
    
    #generate dictionary
    dirDict = dict((key, value) for (key, value) in zip(keyList, dirList))
    
    #print file list
    print('{:<10s}{:<40s}{:<20s}'.format('Option','Name','Size'))
    for key, value in dirDict.items():
        print('{:<10d}{:<40s}{:<20s}'.format(key, value.split(" ")[0], value.split(" ")[1]))
        
    #select option of file to be transfered
    option = int(input("Select option of file to be selected"))

    return option, dirDict

def main():
    host = input(str("Please enter the host address of the sender: "))
    s1 = SocketUnderlay(host)
    print('Connected...')

    #receive file listing
    data_recv = s1.recvData(1024)
    
    dirListString = data_recv.decode('utf-8')
    
    #display list of files
    selection, dirDict = displayFileListing(dirListString)
    
    #convert string to binary
    reqFile = dirDict.get(selection).split(" ")[0].encode('utf-8')
    #send selected selection
    s1.sendData(reqFile)
    
    #prepare to receive file 
    print("to recv ",dirDict.get(selection).split(" ")[0]," of size ",dirDict.get(selection).split(" ")[1]," bytes")
    transBin = s1.recvData(int(dirDict.get(selection).split(" ")[1]))
    with open(dirDict.get(selection).split(" ")[0], 'wb') as f:
        f.write(transBin)



if __name__ == '__main__':
    main()


