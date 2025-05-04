import threading
import ssl
import logging

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from Cryptodome.Util.Padding import pad
from Cryptodome.Cipher import AES
import os
import time
import socket
import requests
from flask import Flask, jsonify, request

# Configura el logger
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', handlers=[
    logging.FileHandler("servidor.log"),
    logging.StreamHandler()
])

#Limita el número de personas en la batalla
semaforo = threading.Semaphore(2)
#Almacena los datos para hacer la batalla
clientes_conectados = []
#Guarda la información de las batallas
historial_batallas = {}
#Evita que dos clientes se conecten a la vez cansando interferencias
lock = threading.Lock()
#Espera a que haya otro conectado
condicion = threading.Condition(lock)

contador = 1

contador_lock = threading.Lock()

def manejar_cliente(cliente_socket, addr):
    global clientes_conectados, historial_batallas, contador

    logging.info(f"[SERVIDOR TCP] Conexión establecida con {addr}")
    enviar_lista_pokemons(cliente_socket)

    #Bloquea el semáforo
    if not semaforo.acquire(blocking=False):
        logging.info(f"[SERVIDOR TCP] Cliente {addr} en espera por semáforo")
        cliente_socket.send("Servidor ocupado, esperando turno...".encode())
        semaforo.acquire()

    try:

        #Recibe pokemon
        mensaje = cliente_socket.recv(1024).decode()
        logging.info(f"[SERVIDOR TCP] Mensaje recibido de {addr}: {mensaje}")

        with lock:
            #Guarda la info
            clientes_conectados.append((cliente_socket, mensaje, addr))
            #Si no hay otro, espera
            if len(clientes_conectados) < 2:
                cliente_socket.send("Esperando otro jugador...".encode())
                condicion.wait()
            #Si hay otro, empieza la batalla
            else:
                condicion.notify_all()
                cliente_socket.send("Otro jugador encontrado!".encode())

        #Simula espera
        cliente_socket.send("Comienza la batalla".encode())

        #Empieza la batalla
        time.sleep(15)
        with lock:
            if len(clientes_conectados) == 2:
                #Obtiene la información
                (sock1, poke1, addr1), (sock2, poke2, addr2) = clientes_conectados
                p1_exp = obtener_datos(poke1)
                p2_exp = obtener_datos(poke2)

                #Compara
                if p1_exp > p2_exp:
                    ganador = poke1
                elif p2_exp > p1_exp:
                    ganador = poke2
                else:
                    ganador = "Empate"

                resultado = {
                    "id_batalla": contador,
                    "jugador1": poke1,
                    "puntos1": p1_exp,
                    "jugador2": poke2,
                    "puntos2": p2_exp,
                    "ganador": ganador
                }
                #Guarda el resultado
                historial_batallas[resultado["id_batalla"]] = resultado
                logging.info(f"[SERVIDOR TCP] {poke1} ({p1_exp}) vs {poke2} ({p2_exp}) - Ganador: {ganador}")

                with contador_lock:
                    contador += 1  # Incremento seguro
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
        logging.error(f"[SERVIDOR TCP] Error con {addr}: {e}")

    finally:
        #Se asegura de cerrar la conexión incluso si hubo error
        logging.info(f"[SERVIDOR TCP] Cerrando conexión con {addr}")
        try:
            cliente_socket.close()
        except:
            pass
        with lock:
            if (cliente_socket, mensaje, addr) in clientes_conectados:
                clientes_conectados.remove((cliente_socket, mensaje, addr))
        semaforo.release()

def obtener_nombres_pokemons(limit=20):
    url = f"https://pokeapi.co/api/v2/pokemon?limit={limit}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        nombres = [pokemon["name"].capitalize() for pokemon in data["results"]]
        return nombres
    except requests.RequestException as e:
        logging.error(f"Error al obtener Pokémon de la API: {e}")
        return ["Pikachu", "Charmander", "Bulbasaur"]  # fallback

def enviar_lista_pokemons(cliente_socket, cantidad=20):
    pokemons_disponibles = obtener_nombres_pokemons(cantidad)
    lista = "Pokémons disponibles:\n" + "\n".join(f"- {p}" for p in pokemons_disponibles)
    try:
        cliente_socket.send(lista.encode())
    except Exception as e:
        logging.error(f"Error al enviar lista de pokémons: {e}")

def obtener_datos(nombre):
    # Obtiene los datos a comparar posteriormente
    url = f"https://pokeapi.co/api/v2/pokemon/{nombre.lower()}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            # Verificar si "base_experience" está presente
            if "base_experience" in data:
                base_exp = data["base_experience"]
                logging.info(f"[DEBUG] Datos obtenidos para {nombre}: base_experience = {base_exp}")
                return base_exp
            else:
                logging.warning(f"[DEBUG] 'base_experience' no encontrado en la respuesta para {nombre}")
        else:
            logging.warning(f"[DEBUG] Error en la API para {nombre}: Código de estado {response.status_code}, nombre no encontrado")
    except Exception as e:
        logging.error(f"[DEBUG] Excepción al obtener datos para {nombre}: {e}")

    return 0


def servidor_tcp_hilos():

    host = "127.0.0.1"
    port = 5001

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
    except FileNotFoundError:
        logging.error("Error: Certificado o clave no encontrados. Usa openssl para generarlos.")
        return

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)

    logging.info("[SERVIDOR TCP] Esperando conexiones...")

    while True:
        client_socket, addr = server_socket.accept()
        try:
            connstream = context.wrap_socket(client_socket, server_side=True)
            threading.Thread(target=manejar_cliente, args=(connstream, addr)).start()
        except ssl.SSLError as ssl_err:
            logging.error("[SERVIDOR] Error SSL:", ssl_err)
            client_socket.close()


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
    logging.info("[SERVIDOR UDP] Esperando mensajes en el puerto 5000...")

    while True:
        try:
            #1. Recibe solicitud
            datos, addr = s.recvfrom(1024)
            logging.info(f"[SERVIDOR UDP] Mensaje recibido de {addr}: {datos.decode()}")

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
            for id_batalla, batalla in historial_batallas.items():
                respuesta += f"ID {id_batalla}: {batalla['jugador1']} ({batalla['puntos1']}) vs {batalla['jugador2']} ({batalla['puntos2']}) -> Ganador: {batalla['ganador']}\n"

            #6. Cifra y envia
            iv = os.urandom(16)
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            mensaje_cifrado = cipher.encrypt(pad(respuesta.encode(), AES.block_size))
            s.sendto(iv + mensaje_cifrado, addr)
            logging.info("[SERVIDOR UDP] Historial enviado.")

        except Exception as e:
            logging.error(f"[SERVIDOR UDP][ERROR]: {e}")

app = Flask(__name__)
@app.route('/batallas', methods=['GET'])
def get_batallas():
    return jsonify(list(historial_batallas.values()))  # devuelve una lista de batallas

@app.route('/batallas/<int:id>', methods=['GET'])
def get_batalla(id):
    batalla = historial_batallas.get(id)
    if batalla:
        return jsonify(batalla)
    return jsonify({"error": "Batalla no encontrada"}), 404

@app.route('/batallas', methods=['POST'])
def post_batalla():
    nueva = request.json
    id_batalla = nueva.get("id_batalla")
    if id_batalla is None:
        return jsonify({"error": "id_batalla requerido"}), 400
    if id_batalla in historial_batallas:
        return jsonify({"error": "Ya existe una batalla con ese id"}), 400
    historial_batallas[id_batalla] = nueva
    return jsonify({"mensaje": "Batalla añadida"}), 201

@app.route('/batallas/<int:id>', methods=['PUT'])
def update_batalla(id):
    if id in historial_batallas:
        historial_batallas[id] = request.json
        return jsonify({"mensaje": "Batalla actualizada"})
    return jsonify({"error": "Batalla no encontrada"}), 404

@app.route('/batallas/<int:id>', methods=['DELETE'])
def delete_batalla(id):
    if id in historial_batallas:
        eliminada = historial_batallas.pop(id)
        return jsonify({"mensaje": "Batalla eliminada", "batalla": eliminada})
    return jsonify({"error": "Batalla no encontrada"}), 404


if __name__ == "__main__":
    hilo_tcp = threading.Thread(target=servidor_tcp_hilos)
    hilo_udp = threading.Thread(target=servidor_udp)

    hilo_tcp.start()
    hilo_udp.start()
    app.run(port=5002, debug=True, use_reloader=False)

    hilo_tcp.join()
    hilo_udp.join()
