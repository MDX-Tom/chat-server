from chat_server import ChatServerUDP


def main():
    udp = ChatServerUDP()
    udp.open()


if __name__ == "__main__":
    main()
