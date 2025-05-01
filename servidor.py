import threading

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from Cryptodome.Util.Padding import pad
from Cryptodome.Cipher import AES
import os
import time
import socket
import requests

#Limita el número de personas en la batalla
semaforo = threading.Semaphore(2)
#Almacena los datos para hacer la batalla
clientes_conectados = []
#Guarda la información de las batallas
historial_batallas = []
#Evita que dos clientes se conecten a la vez cansando interferencias
lock = threading.Lock()
#Espera a que haya otro conectado
condicion = threading.Condition(lock)

def manejar_cliente(cliente_socket, addr):
    global clientes_conectados, historial_batallas

    print(f"[SERVIDOR TCP] Conexión establecida con {addr}")

    #Bloquea el semáforo
    if not semaforo.acquire(blocking=False):
        print(f"[SERVIDOR TCP] Cliente {addr} en espera por semáforo")
        cliente_socket.send("Servidor ocupado, esperando turno...".encode())
        semaforo.acquire()

    try:
        #Recibe pokemon
        mensaje = cliente_socket.recv(1024).decode()
        print(f"[SERVIDOR TCP] Mensaje recibido de {addr}: {mensaje}")

        with lock:
            #Guarda la info
            clientes_conectados.append((cliente_socket, mensaje, addr))
            #Si no hay otro, espera
            if len(clientes_conectados) < 2:
                print("[SERVIDOR TCP] Esperando otro cliente...")
                cliente_socket.send("Esperando otro jugador...".encode())
                condicion.wait()
            #Si hay otro, empieza la batalla
            else:
                condicion.notify_all()
                cliente_socket.send("Otro jugador encontrado".encode())

        #Simula espera
        #Empieza la batalla
        time.sleep(10)
        with lock:
            if len(clientes_conectados) == 2:
                #Obtiene la información
                (sock1, poke1, addr1), (sock2, poke2, addr2) = clientes_conectados
                p1_exp = obtener_datos(poke1)
                p2_exp = obtener_datos(poke2)

                #Compara
                print(f"[SERVIDOR TCP] {poke1} ({p1_exp}) vs {poke2} ({p2_exp})")
                if p1_exp > p2_exp:
                    ganador = poke1
                elif p2_exp > p1_exp:
                    ganador = poke2
                else:
                    ganador = "Empate"

                resultado = {
                    "jugador1": poke1,
                    "puntos1": p1_exp,
                    "jugador2": poke2,
                    "puntos2": p2_exp,
                    "ganador": ganador
                }
                #Guarda el resultado
                historial_batallas.append(resultado)

                #Manda el resultado
                msg1 = f"Resultado: {poke1} ({p1_exp}) vs {poke2} ({p2_exp}). Ganador: {ganador}"
                msg2 = f"Resultado: {poke1} ({p1_exp}) vs {poke2} ({p2_exp}). Ganador: {ganador}"

                sock1.send(msg1.encode())
                sock2.send(msg2.encode())

                sock1.close()
                sock2.close()
                clientes_conectados.clear()

                # Libera el semáforo dos veces porque se adquirió dos veces (una por cada cliente)
                semaforo.release()
                semaforo.release()
                return

    except Exception as e:
        print(f"[SERVIDOR TCP] Error con {addr}: {e}")

    finally:
        #Se asegura de cerrar la conexión incluso si hubo error
        print(f"[SERVIDOR TCP] Cerrando conexión con {addr}")
        try:
            cliente_socket.close()
        except:
            pass
        with lock:
            if (cliente_socket, mensaje, addr) in clientes_conectados:
                clientes_conectados.remove((cliente_socket, mensaje, addr))
        semaforo.release()

def obtener_datos(nombre):
    #Obtiene los datos a comparar posteriormente
    url = f"https://pokeapi.co/api/v2/pokemon/{nombre.lower()}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return data["base_experience"]
    except:
        pass
    return 0

def servidor_tcp_hilos():

    host = "127.0.0.1"
    port = 5001
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)

    print("[SERVIDOR TCP] Esperando conexiones...")

    while True:
        #Crea un nuevo hilo para cada cliente que se conecta
        cliente_socket, addr = server_socket.accept()
        cliente_hilo = threading.Thread(target=manejar_cliente, args=(cliente_socket, addr))
        cliente_hilo.start()

def servidor_udp():
    global historial_batallas

    # Generar par de claves RSA una sola vez
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    pem_publica = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 5000))
    print("[SERVIDOR UDP] Esperando mensajes en el puerto 5000...")

    while True:
        try:
            #1. Recibe solicitud
            datos, addr = s.recvfrom(1024)
            print(f"[SERVIDOR UDP] Mensaje recibido de {addr}: {datos.decode()}")

            #2. Envia clave pública
            s.sendto(pem_publica, addr)

            #3. Recibe clave AES cifrada
            encrypted_aes_key, _ = s.recvfrom(256)

            #4. Descifra clave AES
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            #5. Prepara el historial
            respuesta = "Historial de batallas:\n"
            for i, batalla in enumerate(historial_batallas):
                respuesta += f"{i + 1}. {batalla['jugador1']} ({batalla['puntos1']}) vs {batalla['jugador2']} ({batalla['puntos2']}) -> Ganador: {batalla['ganador']}\n"

            #6. Cifra y envia
            iv = os.urandom(16)
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            mensaje_cifrado = cipher.encrypt(pad(respuesta.encode(), AES.block_size))
            s.sendto(iv + mensaje_cifrado, addr)
            print("[SERVIDOR UDP] Mensaje cifrado enviado.")

        except Exception as e:
            print(f"[SERVIDOR UDP][ERROR]: {e}")


if __name__ == "__main__":
    hilo_tcp = threading.Thread(target=servidor_tcp_hilos)
    hilo_udp = threading.Thread(target=servidor_udp)

    hilo_tcp.start()
    hilo_udp.start()

    hilo_tcp.join()
    hilo_udp.join()


