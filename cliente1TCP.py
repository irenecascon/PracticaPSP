import socket
import ssl

def cliente_tcp_ssl():
    host = "127.0.0.1"
    port = 5001

    # Crear el contexto SSL
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # No verifica el certificado (solo para pruebas locales)

    # Crear socket TCP normal
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Envolver con SSL
    conn = context.wrap_socket(sock, server_hostname=host)

    try:
        conn.connect((host, port))
        print("[CLIENTE] Conectado al servidor mediante SSL.")
        lista = conn.recv(2048).decode()
        print("[CLIENTE] Lista de Pokémons disponibles:\n" + lista)
        mensaje = input("Introduce el nombre del Pokémon: ")
        conn.send(mensaje.encode())

        # Recibir mensajes
        while True:
            msg = conn.recv(1024)
            if not msg:
                break
            print("[CLIENTE] Recibe:", msg.decode())

    except Exception as e:
        print("[CLIENTE] Error:", e)

    finally:
        print("[CLIENTE] Cerrando conexión.")
        conn.close()

cliente_tcp_ssl()


