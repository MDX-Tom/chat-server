from enum import Enum
from struct import Struct, calcsize

from header_server import ChatContentType, Status, HeaderBase

########################################################################
# ENUM
########################################################################


class ClientMsgType(Enum):
    MSG_CLIENT_ACK = 10  # Reliable UDP

    CHAT_CONTENT_CLIENT = 20
    LOGIN_REQUEST = 30
    LOGOUT_REQUEST = 40

    CHAT_REQUEST = 100


########################################################################
# LOGIN REQUEST
########################################################################


class LoginRequestHeader:
    def __init__(self):
        self.struct = "@HHBH28s"

        self.headerSize = calcsize(self.struct)
        self.packetSize = self.headerSize
        self.msgType = ClientMsgType.LOGIN_REQUEST.value

        self.thisUserID = 0
        self.password = "0123456789012345678901234"


'''
    struct LoginRequestHeader
    {
        quint16 headerSize = sizeof(LoginRequestHeader); // in bytes
        quint16 packetSize; // in bytes (= headerSize + payloadSize)
        quint8 msgType = ClientMsgType::LOGIN_REQUEST;

        quint16 thisUserID;
        quint8 password[25];
    };
'''

########################################################################
# LOGOUT REQUEST
########################################################################


class LogoutRequestHeader:
    def __init__(self):
        self.struct = "@HHBH"

        self.headerSize = calcsize(self.struct)
        self.packetSize = self.headerSize
        self.msgType = ClientMsgType.LOGOUT_REQUEST.value

        self.thisUserID = 0


'''
    struct LogoutRequestHeader
    {
        quint16 headerSize = sizeof(LogoutRequestHeader); // in bytes
        quint16 packetSize; // in bytes (= headerSize + payloadSize)
        quint8 msgType = ClientMsgType::LOGOUT_REQUEST;

        quint16 thisUserID;
    };
'''

########################################################################
# ChatContent (Text)
########################################################################


class TextMsgHeader:
    def __init__(self):
        self.struct = "@HHBHHH"

        self.headerSize = calcsize(self.struct)
        self.packetSize = self.headerSize
        self.msgType = ClientMsgType.CHAT_CONTENT_CLIENT.value

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
        self.struct = "@HHBHHBII"

        self.headerSize = calcsize(self.struct)
        self.packetSize = self.headerSize
        self.msgType = ClientMsgType.CHAT_CONTENT_CLIENT.value

        self.fromUserID = 0
        self.targetUserID = 0
        self.contentType = ChatContentType.FILE.value

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
        self.struct = "@HHBH"

        self.headerSize = calcsize(self.struct)
        self.packetSize = self.headerSize
        self.msgType = ClientMsgType.CHAT_REQUEST.value

        self.thisUserID = 0


'''
    struct ChatRequestHeader
    {
        quint16 headerSize = sizeof(ChatRequestHeader); // in bytes
        quint16 packetSize; // in bytes (= headerSize + payloadSize)
        quint8 msgType = ClientMsgType::CHAT_REQUEST;

        quint16 thisUserID;
    };
'''
