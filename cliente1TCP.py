import socket
import requests

#Manda el nombre de un pokemon
def cliente_tcp():
    #Crea socket
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.connect(("127.0.0.1", 5001))
    print("[CLIENTE] Conectado al servidor.")

    mensaje = input("Introduce el nombre del pokemon:")
    c.send(mensaje.encode())

    #Recibe mensajes del servidor hasta que cierre la conexión
    try:
        while True:
            msg = c.recv(1024)
            if not msg:
                break
            print("[CLIENTE] Recibe:", msg.decode())
    except Exception as e:
        print("[CLIENTE] Error al recibir datos:", e)

    print("[CLIENTE] Cerrando conexión.")
    c.close()


cliente_tcp()

