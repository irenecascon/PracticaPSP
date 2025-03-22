import socket
import threading
import time

# Semáforo para controlar el número máximo de clientes en proceso
semaforo = threading.Semaphore(2)
# Lista para almacenar los clientes conectados
clientes_conectados = []
# Lock para evitar condiciones de carrera al modificar la lista de clientes
lock = threading.Lock()
# Condición para sincronizar los clientes y esperar a que haya dos conectados
condicion = threading.Condition(lock)


def manejar_cliente(cliente_socket, addr):
    global clientes_conectados

    print(f"[SERVIDOR] Conexión establecida con {addr}")

    if not semaforo.acquire(blocking=False):
        print(f"[SERVIDOR] Cliente {addr} en espera por semáforo")
        cliente_socket.send("Servidor ocupado, esperando turno...".encode())
        semaforo.acquire()

    try:
        mensaje = cliente_socket.recv(1024).decode()
        print(f"[SERVIDOR] Mensaje recibido de {addr}: {mensaje}")

        with lock:
            clientes_conectados.append(cliente_socket)
            # Si hay menos de dos clientes conectados, el primero espera
            if len(clientes_conectados) < 2:
                print("[SERVIDOR] Esperando otro cliente...")
                cliente_socket.send("Esperando otro jugador...".encode())
                condicion.wait()
            else:
                # Cuando hay dos clientes, se notifica a ambos
                cliente_socket.send("Otro jugador encontrado".encode())
                condicion.notify_all()

        # Enviar respuesta a cada cliente cuando haya dos conectados
        print("[SERVIDOR] Batalla en curso...")
        cliente_socket.send("Batalla en curso".encode())
        time.sleep(10)
        respuesta = "Resultado batalla"
        cliente_socket.send(respuesta.encode())

        with lock:
            clientes_conectados.remove(cliente_socket)

    except Exception as e:
        print(f"[SERVIDOR] Error con {addr}: {e}")

    print(f"[SERVIDOR] Cerrando conexión con {addr}")
    cliente_socket.close()
    semaforo.release()


def servidor_tcp_hilos():
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind(("127.0.0.1", 5001))
    servidor.listen(5)

    print("[SERVIDOR] Esperando conexiones...")

    while True:
        cliente_socket, addr = servidor.accept()
        cliente_hilo = threading.Thread(target=manejar_cliente, args=(cliente_socket, addr))
        cliente_hilo.start()


servidor_tcp_hilos()




