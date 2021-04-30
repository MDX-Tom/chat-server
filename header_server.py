from enum import Enum
from struct import Struct, calcsize

########################################################################
# ENUM
########################################################################


class ChatContentType(Enum):
    TEXT = 0
    FILE = 1


class ServerMsgType(Enum):
    MSG_SERVER_ACK = 1,  # Reliable UDP

    CHAT_CONTENT_SERVER = 0,
    LOGIN_REPLY = 2, LOGOUT_REPLY = 3,
    CHAT_REQUEST_REPLY = 99


class Status(Enum):
    SUCCESS = 1,

    ERROR_PASSWORD_WRONG = 10,
    ERROR_CONFLICT = 11,  # 重复操作

    ERROR = 99


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

        self.md5Hash = "0123456789012345"  # 16 bytes


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
# LOGIN REPLY
########################################################################


class LoginReplyHeader:
    def __init__(self):
        self.struct = "!HHBHB"

        self.headerSize = calcsize(self.struct)
        self.packetSize = self.headerSize
        self.msgType = ServerMsgType.LOGIN_REPLY.value

        self.loginUserID = 0
        self.status = Status.ERROR.value


'''
    struct LoginReplyHeader
    {
        const quint16 headerSize = sizeof(LoginReplyHeader);
        const quint16 packetSize = sizeof(LoginReplyHeader);
        const quint8 msgType = ServerMsgType::LOGIN_REPLY;

        quint16 loginUserID;
        quint8 status;
    };
'''

########################################################################
# LOGOUT REPLY
########################################################################


class LogoutReplyHeader:
    def __init__(self):
        self.struct = "!HHBHB"

        self.headerSize = calcsize(self.struct)
        self.packetSize = self.headerSize
        self.msgType = ServerMsgType.LOGOUT_REPLY.value

        self.logoutUserID = 0
        self.status = Status.ERROR.value


'''
    struct LogoutReplyHeader
    {
        const quint16 headerSize = sizeof(LogoutReplyHeader);
        const quint16 packetSize = sizeof(LogoutReplyHeader);
        const quint8 msgType = ServerMsgType::LOGOUT_REPLY;

        quint16 logoutUserID;
        quint8 status;
    };
'''

########################################################################
# CHAT REQUEST REPLY
########################################################################


class ChatRequestReplyHeader:
    def __init__(self):
        self.struct = "!HHBHH"

        self.headerSize = calcsize(self.struct)
        self.packetSize = self.headerSize
        self.msgType = ServerMsgType.CHAT_REQUEST_REPLY.value

        self.thisUserID = 0
        self.pendingMsgTotalCount = 0


'''
    struct ChatRequestReplyHeader
    {
        const quint16 headerSize = sizeof(ChatRequestReplyHeader);
        quint16 packetSize;
        const quint8 msgType = ServerMsgType::CHAT_REQUEST_REPLY;

        quint16 thisUserID;
        quint16 pendingMsgTotalCount;
    };
'''