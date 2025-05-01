import socket
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
from Cryptodome.Random import get_random_bytes

def cliente_udp():
    #1. Crea socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    servidor = ("127.0.0.1", 5000)
    print("[CLIENTE] Enviando mensaje al servidor: Hola")
    s.sendto("Hola".encode(), servidor)

    #2. Recibe clave pública del servidor
    public_key_pem, _ = s.recvfrom(2048)
    public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())

    #3. Genera clave AES
    aes_key = get_random_bytes(16)

    #4. Cifra clave AES con clave pública RSA
    aes_key_encrypted = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    #5. Envia clave AES cifrada al servidor
    s.sendto(aes_key_encrypted, servidor)

    #6. Recibe datos cifrados
    datos, _ = s.recvfrom(2048)
    iv = datos[:16]
    mensaje_cifrado = datos[16:]

    #7. Descifra mensaje con AES
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    mensaje = unpad(cipher.decrypt(mensaje_cifrado), AES.block_size)
    print(f"[CLIENTE] Historial recibido:\n{mensaje.decode()}")

    s.close()

if __name__ == "__main__":
    cliente_udp()

