#!python3
# -*- coding: UTF-8 -*-
# encoding: utf-8

import socket
import threading
from struct import Struct
import zlib
import hashlib

from chat_data import *
import header_server
import header_client

localIP = "192.168.3.131"
localPort = 8002
remotePort = 8002
udpBufferSize = 1024


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

        # 监听地址和端口
        self.sock.bind((ip, port))

        self.listenEvent = threading.Event()
        self.listenEvent.clear()

        self.listenThread = threading.Thread(target=self.waitForData)
        self.listenThread.start()

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

            try:
                data, addr = self.sock.recvfrom(udpBufferSize)
                print()
                print("receiving from: " + str(addr))
                print("received  data: " + str(data))

                # 新线程处理数据
                newThread = threading.Thread(
                    target=self.ClientDataHandler, args=(data, addr))
                newThread.start()

            except Exception as e:
                print()
                print("ERROR RECEIVING: " + str(e))

    ########################################################################################
    # 处理收到的数据
    ########################################################################################

    def ClientDataHandler(self, data: bytes, addr):
        header = header_server.HeaderBase()
        headerTuple = Struct.unpack(header.struct, data)
        header.headerSize,
        header.packetSize,
        header.msgType = headerTuple

        if header.msgType == header_client.ClientMsgType.LOGIN_REQUEST.value:
            headerRequest = header_client.LoginRequestHeader()

            if header.headerSize != headerRequest.headerSize or header.packetSize != headerRequest.packetSize:
                print("PACKET FORMAT ERROR!!!")
                return

            headerRequestTuple = Struct.unpack(headerRequest.struct, data)
            headerRequest.headerSize,
            headerRequest.packetSize,
            headerRequest.msgType,
            headerRequest.thisUserID,
            headerRequest.password = headerRequestTuple

            self.LoginRequest(headerRequest, addr)

        elif header.msgType == header_client.ClientMsgType.LOGOUT_REQUEST.value:
            headerRequest = header_client.LogoutRequestHeader()

            if header.headerSize != headerRequest.headerSize or header.packetSize != headerRequest.packetSize:
                print("PACKET FORMAT ERROR!!!")
                return

            headerRequestTuple = Struct.unpack(headerRequest.struct, data)
            headerRequest.headerSize,
            headerRequest.packetSize,
            headerRequest.msgType,
            headerRequest.thisUserID = headerRequestTuple

            self.LogoutRequest(headerRequest, addr)

        elif header.msgType == header_client.ClientMsgType.CHAT_CONTENT_CLIENT.value:
            if header.headerSize != header_client.TextMsgHeader().headerSize:
                print("PACKET FORMAT ERROR!!!")
                return

            self.ChatContent(data, addr)

        elif header.msgType == header_client.ClientMsgType.CHAT_REQUEST.value:
            headerRequest = header_client.ChatRequestHeader()

            if header.headerSize != headerRequest.headerSize or header.packetSize != headerRequest.packetSize:
                print("PACKET FORMAT ERROR!!!")
                return

            headerRequestTuple = Struct.unpack(headerRequest.struct, data)
            headerRequest.headerSize,
            headerRequest.packetSize,
            headerRequest.msgType,
            headerRequest.thisUserID = headerRequestTuple

            self.ChatRequest(headerRequest, addr)

    def LoginRequest(self, headerRequest: header_client.LoginRequestHeader, addr):

        headerReply = header_server.LoginReplyHeader()
        headerReply.loginUserID = headerRequest.thisUserID
        headerReply.status = header_server.Status.SUCCESS.value

        if headerRequest.thisUserID not in self.users.keys():
            headerReply.status = header_server.Status.ERROR.value

        # ? elif self.users[headerRequest.thisUserID].loggedIn:
        # ?    headerReply.status = header_server.Status.ERROR_CONFLICT.value

        elif headerRequest.password != self.users[headerRequest.thisUserID].password:
            headerReply.status = header_server.Status.ERROR_PASSWORD_WRONG.value

        else:
            headerReply.status = header_server.Status.SUCCESS.value

            # 绑定登录成功用户的UserID和IP地址、端口
            self.users[headerRequest.thisUserID].loggedIn = True
            self.users[headerRequest.thisUserID].addr = (addr[0], remotePort)

        bytesToSend = Struct.pack(headerReply.struct,
                                  headerReply.headerSize,
                                  headerReply.packetSize,
                                  headerReply.msgType,
                                  headerReply.loginUserID,
                                  headerReply.status)

        self.sock.sendto(
            bytesToSend, self.users[headerRequest.thisUserID].addr)
        print("sent to: " +
              self.users[headerRequest.thisUserID].addr + " - " + bytesToSend.decode('utf-8'))

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

        bytesToSend = Struct.pack(headerReply.struct,
                                  headerReply.headerSize,
                                  headerReply.packetSize,
                                  headerReply.msgType,
                                  headerReply.logoutUserID,
                                  headerReply.status)

        self.sock.sendto(
            bytesToSend, self.users[headerRequest.thisUserID].addr)
        print("sent to: " +
              self.users[headerRequest.thisUserID].addr + " - " + bytesToSend.decode('utf-8'))

    def ChatContent(self, data: bytes, addr):
        # 发送ACK信息
        ackHeader = header_server.PacketReplyHeader()
        ackHeader.md5Hash = md5(data).digest()
        ackHeaderBytes = Struct.pack(ackHeader.struct,
                                     ackHeader.headerSize,
                                     ackHeader.packetSize,
                                     ackHeader.msgType,
                                     ackHeader.md5Hash)
        self.sock.sendto(ackHeaderBytes, (addr[0], remotePort))

        # TEXT消息提交头：尝试解析
        headerContent = header_client.TextMsgHeader()
        headerContentTuple = Struct.unpack(headerContent.struct, data)
        headerContent.contentType = headerContentTuple[5]

        if headerContent.contentType == header_client.ChatContentType.TEXT.value:
            headerContent.headerSize,
            headerContent.packetSize,
            headerContent.msgType,
            headerContent.fromUserID,
            headerContent.targetUserID,
            headerContent.contentType = headerContentTuple

            # todo 处理TEXT信息
            pass

        # FILE消息提交头：尝试TEXT失败，重新以FILE解包
        elif headerContent.contentType == header_client.ChatContentType.FILE.value:
            headerContent = header_client.FileMsgHeader()
            headerContentTuple = Struct.unpack(headerContent.struct, data)

            headerContent.headerSize,
            headerContent.packetSize,
            headerContent.msgType,
            headerContent.fromUserID,
            headerContent.targetUserID,
            headerContent.contentType,
            headerContent.packetCountTotal,
            headerContent.packetCountCurrent = headerContentTuple

            # todo 处理FILE信息
            pass

    def ChatRequest(self, headerRequest: header_client.ChatRequestHeader, addr):
        headerReply = header_server.ChatRequestReplyHeader()
        headerReply.thisUserID = headerRequest.thisUserID

        if headerReply.thisUserID not in self.users.keys():
            headerReply.pendingMsgTotalCount = 0

        else:
            pendingMsg = self.users[headerRequest.thisUserID].pendingTextMsg

            headerReply.pendingMsgTotalCount = len(pendingMsg)

            # todo: 客户端添加ACK回包确认收到了所有消息
            self.users[headerReply.thisUserID].pendingContent.clear()

        # todo: 将具体的包信息打包进去

        bytesToSend = Struct.pack(headerReply.struct,
                                  headerReply.headerSize,
                                  headerReply.packetSize,
                                  headerReply.msgType,
                                  headerReply.thisUserID,
                                  headerReply.pendingMsgTotalCount)

        # todo: 支持多客户端登录同一账号
        self.sock.sendto(bytesToSend, (addr[0], remotePort))
        print("sent to: " +
              self.users[headerRequest.thisUserID].addr + " - " + bytesToSend.decode('utf-8'))


if __name__ == "__main__":
    tcp = ChatServerUDP(localIP)
    tcp.open()
