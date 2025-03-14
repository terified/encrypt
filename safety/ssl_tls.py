import ssl
import socket

def create_ssl_context(certfile, keyfile, cafile=None):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=cafile)
    context.load_cert_chain(certfile, keyfile)
    return context

def start_ssl_server(host, port, certfile, keyfile, cafile=None):
    context = create_ssl_context(certfile, keyfile, cafile)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"SSL server started on {host}:{port}")

    while True:
        client_socket, addr = server_socket.accept()
        ssl_socket = context.wrap_socket(client_socket, server_side=True)
        print(f"Connection from {addr}")
        data = ssl_socket.recv(1024)
        print(f"Received: {data.decode('utf-8')}")
        ssl_socket.send(b"Hello, SSL!")
        ssl_socket.close()

def start_ssl_client(host, port, cafile=None):
    context = ssl.create_default_context(cafile=cafile)
    with socket.create_connection((host, port)) as client_socket:
        with context.wrap_socket(client_socket, server_hostname=host) as ssl_socket:
            ssl_socket.send(b"Hello, SSL server!")
            data = ssl_socket.recv(1024)
            print(f"Received: {data.decode('utf-8')}")

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python ssl_tls.py server|client")
        sys.exit(1)

    mode = sys.argv[1]
    host = 'localhost'
    port = 8443
    certfile = 'server.crt'
    keyfile = 'server.key'
    cafile = 'ca.crt'

    if mode == 'server':
        start_ssl_server(host, port, certfile, keyfile, cafile)
    elif mode == 'client':
        start_ssl_client(host, port, cafile)
    else:
        print("Unknown mode. Use 'server' or 'client'.")
        sys.exit(1)