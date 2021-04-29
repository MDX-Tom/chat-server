from enum import Enum
from struct import Struct, calcsize

########################################################################
# ENUM
########################################################################


class ChatContentType(Enum):
    TEXT = 0
    FILE = 1


class ClientMsgType(Enum):
    MSG_CLIENT_ACK = 1,  # Reliable UDP

    CHAT_CONTENT_CLIENT = 0,
    LOGIN_REQUEST = 2, LOGOUT_REQUEST = 3,
    CHAT_REQUEST = 99,


class ServerMsgType(Enum):
    MSG_SERVER_ACK = 1,  # Reliable UDP

    CHAT_CONTENT_SERVER = 0,
    LOGIN_REPLY = 2, LOGOUT_REPLY = 3,
    CHAT_REQUEST_REPLY = 99

########################################################################
# Base of Headers
########################################################################


class HeaderBase:
    def __init__(self):
        self.struct = "!HHB"

        self.headerSize = calcsize(self.struct)
        self.packetSize = self.headerSize
        self.msgType = 0


'''
    struct HeaderBase
    {
        quint16 headerSize;
        quint16 packetSize;
        quint8 msgType;
    }; 
'''

########################################################################
# PACKET REPLY (ACK Message)
########################################################################


class PacketReplyHeader:
    def __init__(self):
        self.struct = "!HHB16s"

        self.headerSize = calcsize(self.struct)
        self.packetSize = self.headerSize
        self.msgType = ServerMsgType.MSG_SERVER_ACK.value

        self.md5Hash = "0000000000000000"


'''
    struct PacketReplyHeader
    {
        quint16 headerSize = sizeof(PacketReplyHeader);
        quint16 packetSize = sizeof(PacketReplyHeader);
        quint8 msgType = ServerMsgType::MSG_SERVER_ACK;

        unsigned char md5Hash[16];
    };
'''

########################################################################
# LOGIN REQUEST
########################################################################


class LoginRequestHeader:
    def __init__(self):
        self.struct = 0

        self.self.headerSize = calcsize(self.struct)
        self.packetSize = self.headerSize
        self.msgType = ClientMsgType.LOGIN_REQUEST.value

        self.thisUserID = 0
        self.password = ""

########################################################################
# LOGOUT REQUEST
########################################################################

########################################################################
# LOGIN REPLY
########################################################################

########################################################################
# LOGOUT REPLY
########################################################################

########################################################################
# ChatContent (Text)
########################################################################


class TextMsgHeader:
    def __init__(self):
        self.struct = "!HHBHHB"

        self.headerSize = calcsize(self.struct)
        self.packetSize = self.headerSize
        self.msgType = 0

        self.fromUserID = 0
        self.targetUserID = 0
        self.contentType = ChatContentType.TEXT.value


'''
    struct TextMsgHeader
    {
        quint16 headerSize = sizeof(TextMsgHeader); // in bytes
        quint16 packetSize; // in bytes (= headerSize + payloadSize)
        quint8 msgType = ClientMsgType::CHAT_CONTENT_CLIENT;

        quint16 fromUserID;
        quint16 targetUserID;
        quint8 contentType = ChatContentType::TEXT;
    };
'''

########################################################################
# ChatContent (File)
########################################################################


class FileMsgHeader:
    def __init__(self):
        self.struct = "!HHBHHBII"

        self.headerSize = calcsize(self.struct)
        self.packetSize = self.headerSize
        self.msgType = 0

        self.fromUserID = 0
        self.targetUserID = 0
        self.contentType = ChatContentType.File.value

        self.packetCountTotal = 1
        self.packetCountCurrent = 1


'''
    struct FileMsgHeader
    {
        quint16 headerSize = sizeof(FileMsgHeader); // in bytes
        quint16 packetSize; // in bytes (= headerSize + payloadSize)
        quint8 msgType = ClientMsgType::CHAT_CONTENT_CLIENT;

        quint16 fromUserID;
        quint16 targetUserID;
        quint8 contentType = ChatContentType::FILE;

        // 分包信息
        quint32 packetCountTotal;
        quint32 packetCountCurrent;
    };
'''

########################################################################
# CHAT REQUEST
########################################################################


class ChatRequestHeader:
    def __init__(self):
        pass

########################################################################
# CHAT REQUEST REPLY
########################################################################


class ChatRequestReplyHeader:
    def __init__(self):
        pass
