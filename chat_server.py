#!python3
# -*- coding: UTF-8 -*-
# encoding: utf-8

import socket
import threading
import struct
import zlib
import hashlib
import os

from chat_data import *
import header_server
import header_client

localIP = "0.0.0.0"
localPort = 8002
remotePort = 8003

remotePacketSize = 8192
udpBufferSize = 1000000000


def crc32(bytes):
    if isinstance(bytes, str):
        bytes = bytes.encode('utf8')
    return zlib.crc32(bytes) & 0xffffffff


def md5(bytes):
    if isinstance(bytes, str):
        bytes = bytes.encode('utf8')
    return hashlib.md5(bytes)


class ChatServerUDP:

    def __init__(self, ip=localIP, port=localPort):
        # dict: { "00001": ChatUser('00001'), }
        db = ChatDataBase()
        self.users = db.userInfo()
        db.close()

        self.ip, self.port = ip, port

        # IPv4 UDP
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(
            socket.SOL_SOCKET, socket.SO_SNDBUF, udpBufferSize)
        print("UDP Buffer Size: " +
              str(self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)))

        # 监听地址和端口
        self.sock.bind((ip, port))

        self.listenEvent = threading.Event()
        self.listenEvent.clear()

        self.listenThread = threading.Thread(target=self.waitForData)
        self.listenThread.start()

        # FILE暂存
        self.fileDict = {}  # 暂存文件分片
        self.file = {}  # 暂存file.open对象
        self.currentFileName = ""

    def open(self):
        """启动监听"""
        print()
        print("Listening at: " + str(self.ip) + ":" + str(self.port))

        self.listenEvent.set()

    def close(self):
        """关闭监听"""
        self.listenEvent.clear()

        print()
        print("Stopped listening")

    def waitForData(self):
        while True:
            self.listenEvent.wait()

            # try:
            data, addr = self.sock.recvfrom(remotePacketSize)

            # print()
            # print("receiving from: " + str(addr) +
            #      " PACKET SIZE: " + str(len(data)))
            # print("received  data: " + str(data))

            # 新线程处理数据
            # newThread = threading.Thread(
            #    target=self.ClientDataHandler, args=(data, addr))
            # newThread.start()

            self.ClientDataHandler(data, addr)

            # except Exception as e:
            #    print()
            #    print("ERROR RECEIVING: " + str(e))

    ########################################################################################
    # 处理收到的数据
    ########################################################################################

    def ClientDataHandler(self, data: bytes, addr):
        header = header_server.HeaderBase()
        if len(data) < header.headerSize:
            print("IGNORE EMPTY DATAGRAM...")
            return
        headerTuple = struct.unpack(header.struct, data[0:header.headerSize])
        header.headerSize, \
            header.packetSize, \
            header.msgType, \
            placeHolder = headerTuple

        if header.msgType == header_client.ClientMsgType.CHAT_CONTENT_CLIENT.value:
            self.ChatContent(data, addr)

        elif header.msgType == header_client.ClientMsgType.LOGIN_REQUEST.value:
            headerRequest = header_client.LoginRequestHeader()

            if header.headerSize != headerRequest.headerSize or header.packetSize != headerRequest.packetSize:
                print("PACKET FORMAT ERROR!!!")
                return

            headerRequestTuple = struct.unpack(
                headerRequest.struct, data[0:headerRequest.headerSize])
            headerRequest.headerSize, \
                headerRequest.packetSize, \
                headerRequest.msgType, \
                headerRequest.thisUserID, \
                headerRequest.password = headerRequestTuple

            headerRequest.password = headerRequest.password.decode("utf-8")

            self.LoginRequest(headerRequest, addr)

        elif header.msgType == header_client.ClientMsgType.LOGOUT_REQUEST.value:
            headerRequest = header_client.LogoutRequestHeader()

            if header.headerSize != headerRequest.headerSize or header.packetSize != headerRequest.packetSize:
                print("PACKET FORMAT ERROR!!!")
                return

            headerRequestTuple = struct.unpack(
                headerRequest.struct, data[0:headerRequest.headerSize])
            headerRequest.headerSize, \
                headerRequest.packetSize, \
                headerRequest.msgType, \
                headerRequest.thisUserID = headerRequestTuple

            self.LogoutRequest(headerRequest, addr)

        elif header.msgType == header_client.ClientMsgType.CHAT_REQUEST.value:
            headerRequest = header_client.ChatRequestHeader()

            if header.headerSize != headerRequest.headerSize or header.packetSize != headerRequest.packetSize:
                print("PACKET FORMAT ERROR!!!")
                return

            headerRequestTuple = struct.unpack(
                headerRequest.struct, data[0:headerRequest.headerSize])
            headerRequest.headerSize, \
                headerRequest.packetSize, \
                headerRequest.msgType, \
                headerRequest.thisUserID = headerRequestTuple

            self.ChatRequest(headerRequest, addr)

    def LoginRequest(self, headerRequest: header_client.LoginRequestHeader, addr):

        headerReply = header_server.LoginReplyHeader()
        headerReply.loginUserID = headerRequest.thisUserID
        headerReply.status = header_server.Status.SUCCESS.value
        bytesFriends = bytes()

        if headerRequest.thisUserID not in self.users.keys():
            headerReply.status = header_server.Status.ERROR.value

        # ? elif self.users[headerRequest.thisUserID].loggedIn:
        # ?    headerReply.status = header_server.Status.ERROR_CONFLICT.value

        elif headerRequest.password != self.users[headerRequest.thisUserID].password.ljust(
                len(headerRequest.password), '\x00'):
            headerReply.status = header_server.Status.ERROR_PASSWORD_WRONG.value

        else:
            headerReply.status = header_server.Status.SUCCESS.value

            # 绑定登录成功用户的UserID和IP地址、端口
            self.users[headerRequest.thisUserID].loggedIn = True
            self.users[headerRequest.thisUserID].addr = (addr[0], remotePort)
            headerReply.friendCount = len(
                self.users[headerRequest.thisUserID].friends)

            for id in self.users[headerRequest.thisUserID].friends:
                bytesFriends += struct.pack("@H", id)

        bytesToSend = struct.pack(headerReply.struct,
                                  headerReply.headerSize,
                                  headerReply.packetSize,
                                  headerReply.msgType,
                                  headerReply.loginUserID,
                                  headerReply.status,
                                  headerReply.friendCount)
        bytesToSend = bytesToSend + bytesFriends

        self.sock.sendto(
            bytesToSend, (addr[0], remotePort))
        print("sent to: " +
              str((addr[0], remotePort)) + " - " + str(bytesToSend))

    def LogoutRequest(self, headerRequest: header_client.LogoutRequestHeader, addr):

        headerReply = header_server.LogoutReplyHeader()
        headerReply.logoutUserID = headerRequest.thisUserID
        headerReply.status = header_server.Status.SUCCESS.value

        if headerRequest.thisUserID not in self.users.keys():
            headerReply.status = header_server.Status.ERROR.value

        # ? elif not self.users[headerRequest.thisUserID].loggedIn:
        # ?    headerReply.status = header_server.Status.ERROR_CONFLICT.value

        else:
            headerReply.status = header_server.Status.SUCCESS.value

            # 解绑用户的UserID和IP地址、端口
            self.users[headerRequest.thisUserID].loggedIn = False
            self.users[headerRequest.thisUserID].addr = None
            # todo: 支持多客户端登陆

        bytesToSend = struct.pack(headerReply.struct,
                                  headerReply.headerSize,
                                  headerReply.packetSize,
                                  headerReply.msgType,
                                  headerReply.logoutUserID,
                                  headerReply.status)

        self.sock.sendto(
            bytesToSend, (addr[0], remotePort))
        print("sent to: " +
              str((addr[0], remotePort)) + " - " + str(bytesToSend))

    def ChatContent(self, data: bytes, addr):
        # 尝试以FILE解析
        headerContent = header_client.FileMsgHeader()
        if headerContent.headerSize < len(data):
            headerContentTuple = struct.unpack(
                headerContent.struct, data[0:headerContent.headerSize])
            headerContent.contentType = headerContentTuple[6]
        else:
            headerContent = header_client.TextMsgHeader()
            headerContentTuple = struct.unpack(
                headerContent.struct, data[0:headerContent.headerSize])
            headerContent.contentType = headerContentTuple[5]

        # FILE消息提交头
        if headerContent.contentType == header_client.ChatContentType.FILE.value:
            headerContent.headerSize, \
                headerContent.packetSize, \
                headerContent.msgType, \
                placeHolder, \
                headerContent.fromUserID, \
                headerContent.targetUserID, \
                headerContent.contentType, \
                headerContent.fileNameLength, \
                headerContent.packetCountTotal, \
                headerContent.packetCountCurrent = headerContentTuple

            # 发送ACK信息
            ackHeader = header_server.FilePacketReplyHeader()
            # ackHeader.md5Hash = md5(data).digest()
            ackHeader.filePacketSeq = headerContent.packetCountCurrent
            ackHeaderBytes = struct.pack(ackHeader.struct,
                                         ackHeader.headerSize,
                                         ackHeader.packetSize,
                                         ackHeader.msgType,
                                         # ackHeader.md5Hash
                                         ackHeader.filePacketSeq)
            self.sock.sendto(ackHeaderBytes, (addr[0], remotePort))
            # print("sent ACK MESSAGE to: " +
            #      str((addr[0], remotePort)) + ", filePacketSeq=" + str(ackHeader.filePacketSeq))

            # 紧跟Header是文件名
            structFileName = "@" + str(headerContent.fileNameLength) + "s"
            fileNameBytes = struct.unpack(
                structFileName, data[headerContent.headerSize:headerContent.headerSize + headerContent.fileNameLength])[0]
            fileNameStr = str(fileNameBytes, encoding="utf-8")

            # 文件名后面直到包结尾是文件分片的Bytes
            fragmentLength = headerContent.packetSize - \
                headerContent.fileNameLength - headerContent.headerSize
            structFragment = "@" + str(fragmentLength) + "s"
            fragmentBytes = struct.unpack(
                structFragment, data[headerContent.headerSize + headerContent.fileNameLength:len(data)])[0]

            # 在内存中暂存分片信息
            if headerContent.packetCountCurrent == 1:
                # 文件名防冲突
                # ! 要求一次只发一个文件
                fileRename = 1
                fileNameRename = fileNameStr
                if not os.path.exists("./Received/"):
                    os.mkdir("./Received/")

                '''
                while fileNameRename in self.fileDict.keys() or os.path.exists("./Received/" + fileNameRename):
                    fileNameRename = fileNameStr + "(" + str(fileRename) + ")"
                    fileRename += 1
                fileNameStr = fileNameRename
                '''

                if os.path.exists("./Received/" + fileNameRename):
                    print("文件已存在，即将覆盖！文件名：" + fileNameRename)
                    os.remove("./Received/" + fileNameRename)

                # 创建文件
                print("New File: " + fileNameStr)
                # ! 要求一次只发一个文件
                self.currentFileName = fileNameStr

                self.fileDict[self.currentFileName] = {}
                self.file[self.currentFileName] = ""

            # ! 要求一次只发一个文件
            if not self.fileDict[self.currentFileName] == "FILE WRITTEN!":
                self.fileDict[self.currentFileName][headerContent.packetCountCurrent] = fragmentBytes

            # 传输完成
            # ! 要求一次只发一个文件
            # ! 发送端发完文件还需要单独发一个“发送结束包”，此包packetCountCurrent超出范围即可
            if headerContent.packetCountCurrent > headerContent.packetCountTotal:
                if not self.file[self.currentFileName] == "FILE WRITTEN!":

                    # 储存文件
                    self.file[self.currentFileName] = open(
                        "./Received/" + fileNameStr, mode="ab")
                    packetLost = 0
                    for i in range(1, headerContent.packetCountTotal + 1):
                        if i not in self.fileDict[self.currentFileName].keys():
                            # 文件不完整
                            packetLost += 1

                        else:
                            self.file[self.currentFileName].write(
                                self.fileDict[self.currentFileName][i])

                    if packetLost == 0:
                        print("FILE: " + self.currentFileName + " RECV SUCCESS!")
                    else:
                        print("FILE: " + self.currentFileName +
                              " RECV FAILED, PACKET LOST: " + str(packetLost))

                    # 删除内存暂存区
                    # todo 需要如何才能更好地防文件名冲突？
                    self.file[self.currentFileName].close()
                    self.file[self.currentFileName] = "FILE WRITTEN!"
                    self.fileDict[self.currentFileName] = "FILE WRITTEN!"

        elif headerContent.contentType == header_client.ChatContentType.TEXT.value:
            headerContent.headerSize, \
                headerContent.packetSize, \
                headerContent.msgType, \
                headerContent.fromUserID, \
                headerContent.targetUserID, \
                headerContent.contentType, \
                headerContent.textPacketSeq = headerContentTuple

            # 发送ACK信息
            ackHeader = header_server.TextPacketReplyHeader()
            # ackHeader.md5Hash = md5(data).digest()
            ackHeader.textPacketSeq = headerContent.textPacketSeq
            ackHeaderBytes = struct.pack(ackHeader.struct,
                                         ackHeader.headerSize,
                                         ackHeader.packetSize,
                                         ackHeader.msgType,
                                         # ackHeader.md5Hash
                                         ackHeader.textPacketSeq)
            self.sock.sendto(ackHeaderBytes, (addr[0], remotePort))
            # print("sent ACK MESSAGE to: " +
            #      str((addr[0], remotePort)) + ", textPacketSeq=" + str(ackHeader.textPacketSeq))

            textSize = headerContent.packetSize - headerContent.headerSize
            structText = "@" + str(textSize) + "s"  # no alignment needed!
            textBytes = struct.unpack(
                structText, data[headerContent.headerSize:len(data)])[0]
            textStr = str(textBytes, encoding="utf-8")

            # 处理TEXT信息
            if headerContent.targetUserID == 0:
                # message to server
                print("SERVER RECEIVE MESSAGE: " + textStr)

            else:
                if headerContent.targetUserID not in self.users.keys():
                    print("Text msg from: " + str(headerContent.fromUserID) +
                          " to: " + str(headerContent.targetUserID) + " (TARGET USER NOT DEFINED!)")
                    return

                # todo: 装入暂存区
                self.users[headerContent.targetUserID].pendingTextMsg.append()

                print("Text msg from: " + str(headerContent.fromUserID) +
                      " to: " + str(headerContent.targetUserID) + "...")

    def ChatRequest(self, headerRequest: header_client.ChatRequestHeader, addr):
        headerReply = header_server.ChatRequestReplyHeader()
        headerReply.thisUserID = headerRequest.thisUserID

        if headerReply.thisUserID not in self.users.keys():
            headerReply.pendingMsgTotalCount = 0

        else:
            pendingMsg = self.users[headerRequest.thisUserID].pendingTextMsg

            headerReply.pendingMsgTotalCount = len(pendingMsg)

            # todo: 客户端添加ACK回包确认收到了所有消息
            self.users[headerReply.thisUserID].pendingTextMsg.clear()

        # todo: 将具体的包信息打包进去

        bytesToSend = struct.pack(headerReply.struct,
                                  headerReply.headerSize,
                                  headerReply.packetSize,
                                  headerReply.msgType,
                                  headerReply.thisUserID,
                                  headerReply.pendingMsgTotalCount)

        # todo: 支持多客户端登录同一账号
        self.sock.sendto(bytesToSend, (addr[0], remotePort))
        print("sent to: " +
              str((addr[0], remotePort)) + " - " + str(bytesToSend))


if __name__ == "__main__":
    udp = ChatServerUDP(localIP)
    udp.open()
