#!python3
# -*- coding: UTF-8 -*-
# encoding: utf-8

import socket
import threading
from struct import Struct
import zlib
import hashlib

from chat_data import *
from udp_packet_headers import *

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
        # { "00001": ChatUser('00001'), }
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

                # 发送ACK信息
                ackHeader = PacketReplyHeader()
                ackHeader.md5Hash = md5(data).digest()
                ackHeaderBytes = Struct.pack(ackHeader.struct, ackHeader.headerSize,
                                             ackHeader.packetSize, ackHeader.msgType, ackHeader.md5Hash)
                self.sock.sendto(ackHeaderBytes, addr)

                # 新线程处理数据
                newThread = threading.Thread(
                    target=UDPDataHandler.ClientDataHandler, args=(data, addr))
                newThread.start()

            except Exception as e:
                print()
                print("ERROR RECEIVING: " + str(e))


class UDPDataHandler:

    def ClientDataHandler(self, data: bytes, addr):
        header = HeaderBase()
        headerTuple = Struct.unpack(header.struct, data)
        header.headerSize, header.packetSize, header.msgType = headerTuple

        if header.msgType == ClientMsgType.LOGIN_REQUEST.value:
            pass

        elif header.msgType == ClientMsgType.LOGOUT_REQUEST.value:
            pass

        elif header.msgType == ClientMsgType.CHAT_CONTENT_CLIENT.value:
            pass

        elif header.msgType == ClientMsgType.CHAT_REQUEST.value:
            pass

    def LoginRequest(self, thisUserID: str, password: str, conn: socket):
        if thisUserID not in self.users.keys():
            dictToSend = {
                'msgType': ServerMsgType.LOGIN_REPLY.value,
                'status': 'error_no_user',
            }

            ''' 
        elif self.users[thisUserID].loggedIn:
            dictToSend = {
                'msgType': ServerMsgType.LOGIN_REPLY.value,
                'status': 'error_already_logged_in',
                
            }
            '''

        elif password != self.users[thisUserID].password:
            dictToSend = {
                'msgType': ServerMsgType.LOGIN_REPLY.value,
                'status': 'error_wrong_password',
            }

        else:
            self.users[thisUserID].loggedIn = True

            dictToSend = {
                'msgType': ServerMsgType.LOGIN_REPLY.value,
                'status': 'success',

                'thisUserID': thisUserID,
                'password': self.users[thisUserID].password,
                'nickName': self.users[thisUserID].nickName,
                'friends': self.users[thisUserID].friends,
            }

        bytesToSend = json.dumps(dictToSend).encode("utf-8")

        conn.send(bytesToSend)

        print("sent: " + bytesToSend.decode('utf-8'))
        conn.close()

    def LogoutRequest(self, thisUserID: str, conn: socket):
        if thisUserID not in self.users.keys():
            dictToSend = {
                'msgType': ServerMsgType.LOGOUT_REPLY.value,
                'status': 'error_no_user',
            }

            '''
        elif not self.users[thisUserID].loggedIn:
            dictToSend = {
                'msgType': ServerMsgType.LOGOUT_REPLY.value,
                'status': 'error_already_logged_out',
            }
            '''

        else:
            self.users[thisUserID].loggedIn = False

            dictToSend = {
                'msgType': ServerMsgType.LOGOUT_REPLY.value,
                'status': 'success',
            }

        bytesToSend = json.dumps(dictToSend).encode("utf-8")

        conn.send(bytesToSend)

        print("sent: " + bytesToSend.decode('utf-8'))
        conn.close()

    def ChatContent(self, thisUserID: str, targetUserID: str, contentType: int, content, conn: socket):
        if targetUserID == 'server':
            print("SERVER MESSAGE RECEIVE: " + str(content))
            conn.close()
            return

        if thisUserID not in self.users.keys():
            dictToSend = {
                'msgType': ServerMsgType.LOGIN_REPLY.value,
                'status': 'error_no_user',
            }

            bytesToSend = json.dumps(dictToSend).encode("utf-8")

            conn.send(bytesToSend)

            print("sent: " + bytesToSend.decode('utf-8'))
            conn.close()

        elif not self.users[thisUserID].loggedIn:
            dictToSend = {
                'msgType': ServerMsgType.LOGIN_REPLY.value,
                'status': 'error_not_logged_in',
            }

            bytesToSend = json.dumps(dictToSend).encode("utf-8")

            conn.send(bytesToSend)

            print("sent: " + bytesToSend.decode('utf-8'))
            conn.close()

        else:
            dictToAppend = {
                'fromUserID': thisUserID,
                'contentType': contentType,
                'content': content,
            }

            self.users[targetUserID].pendingContent.append(dictToAppend)
            conn.close()

    def ChatRequest(self, thisUserID: str, conn: socket):
        if thisUserID not in self.users.keys():
            dictToSend = {
                'msgType': ServerMsgType.CHAT_REQUEST_REPLY.value,
                'hasNewContent': False,
            }

        elif len(self.users[thisUserID].pendingContent) == 0:
            dictToSend = {
                'msgType': ServerMsgType.CHAT_REQUEST_REPLY.value,
                'hasNewContent': False,
            }
        else:
            dictToSend = {
                'msgType': ServerMsgType.CHAT_REQUEST_REPLY.value,
                'hasNewContent': True,

                'contentArray': repr(self.users[thisUserID].pendingContent),
            }
            self.users[thisUserID].pendingContent.clear()

        bytesToSend = json.dumps(dictToSend).encode("utf-8")

        conn.send(bytesToSend)

        print("sent: " + bytesToSend.decode('utf-8'))
        conn.close()


if __name__ == "__main__":
    tcp = ChatServerUDP(localIP)
    tcp.open()
