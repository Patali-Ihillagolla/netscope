import platform
import socket



def main():
    print("NetScope v0.1")
    print("Network Inspector")
    print("=================")

    print(f"Operating System: {platform.system()}")

    hostname = socket.gethostname()
    print(f"Hostname : {hostname}")


if __name__ == "__main__":
    main()