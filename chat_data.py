import sqlite3
from sqlite3.dbapi2 import Cursor


class ChatUser:
    def __init__(self, id: int, password: str, nickName: str, friends: list):
        # 用户号码
        self.id = id

        # 密码，暂时为明文
        self.password = password

        # 昵称
        self.nickName = nickName

        # 好友列表 list:[int,]
        self.friends = friends

        # 登录状态
        self.loggedIn = False

        # IP地址和端口
        self.addr = None  # ("0.0.0.0", 0)

        # 新消息暂存区
        self.pendingTextMsg = [

        ]


'''
class ChatGroup:
    def __init__(self, groupID: int):
        # 群组编号
        self.id = groupID

        # 群名
        self.name = "群聊" + groupID

        # 群主
        self.owner = 0

        # 群用户 list:[str,]
        self.users = []
'''


class ChatDataBase:
    def __init__(self, dbName="C:\\Users\\miyua\\chat_udp.db"):
        self.dbName = dbName
        self.conn = sqlite3.connect(self.dbName, timeout=2.0)

        self.cursor = self.conn.cursor()

    def initializeFile(self):
        self.conn = sqlite3.connect(self.dbName, timeout=2.0)
        self.cursor = self.conn.cursor()
        try:
            self.cursor.execute("CREATE TABLE user \
                                (ID             INT PRIMARY KEY     NOT NULL, \
                                 PASSWORD       TEXT                NOT NULL, \
                                 NICKNAME       TEXT                NOT NULL \
                                 )")
        except Exception as e:
            print(e)

        try:
            self.cursor.execute('CREATE TABLE friends \
                                (PAIRID         INT PRIMARY KEY     NOT NULL, \
                                 THISID         INT                 NOT NULL, \
                                 THATID         INT                 NOT NULL \
                                 )')
        except Exception as e:
            print(e)

        self.conn.commit()
        self.conn.close()

    def addUser(self, id: str, password: str, nickName: str, friends: list):
        self.conn = sqlite3.connect(self.dbName, timeout=2.0)
        self.cursor = self.conn.cursor()
        self.cursor.execute("INSERT INTO user (ID, PASSWORD, NICKNAME) \
                             VALUES ('%d', '%s', '%s')" % (id, password, nickName))

        curFriends = self.cursor.execute("SELECT PAIRID FROM friends")
        cntFriendsPair = 0
        for ff in curFriends:
            cntFriendsPair += 1

        for f in friends:
            cntFriendsPair += 1
            self.cursor.execute("INSERT INTO friends (PAIRID, THISID, THATID)  \
                                 VALUES ('%d', '%d', '%d')" % (cntFriendsPair, id, f))
            print("INSERT INTO friends (PAIRID, THISID, THATID)  \
                                 VALUES ('%d', '%d', '%d')" % (cntFriendsPair, id, f))
            '''
            cntFriendsPair += 1
            self.cursor.execute("INSERT INTO friends (PAIRID, THATID, THISID)  \
                                 VALUES ('%d', '%s', '%s')" % (cntFriendsPair, f, id))
            print("INSERT INTO friends (PAIRID, THISID, THATID)  \
                                 VALUES ('%d', '%s', '%s')" % (cntFriendsPair, f, id))
                                 '''

        self.conn.commit()
        self.conn.close()

    def userInfo(self) -> dict:
        self.conn = sqlite3.connect(self.dbName, timeout=2.0)
        self.cursor = self.conn.cursor()
        userInfoDict = {}

        userCursor = self.conn.execute(
            "SELECT ID, PASSWORD, NICKNAME FROM user")
        for user in userCursor:
            id = user[0]
            password = user[1]
            nickName = user[2]

            friendsCursor = self.conn.execute(
                "SELECT THATID FROM friends WHERE THISID = '%s'" % (id))
            friends = [i[0] for i in friendsCursor]

            userInfoDict[id] = ChatUser(id, password, nickName, friends)

        self.conn.close()

        return userInfoDict

    def close(self):
        self.conn.close()


if __name__ == "__main__":

    db = ChatDataBase()
    db.initializeFile()
    db.addUser(1, 'liangleya', '凉了呀', [0, 2, 3])
    db.addUser(2, '00002_pswd', '00002', [0, 1])
    db.addUser(3, '00003_pswd', '00003', [0, 1])
    db.addUser(0, '00000', '服务器', [])
    db.close()

    db = ChatDataBase()
    print(str(db.userInfo()))
    db.close()
