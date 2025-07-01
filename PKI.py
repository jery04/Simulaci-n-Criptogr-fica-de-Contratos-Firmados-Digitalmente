from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from datetime import datetime, UTC
import json

# ======= Funciones de Criptografía =======

def generar_claves():
    """Genera un par de claves (privada, pública)"""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def generar_hash(documento: str):
    """Genera un hash SHA-256 del contenido del documento"""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(documento.encode())
    return digest.finalize()

def firmar_documento(hash_documento: bytes, clave_privada):
    """Firma un hash con la clave privada (firma digital)"""
    return clave_privada.sign(
        hash_documento,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def verificar_firma(hash_documento, firma, clave_publica):
    """Verifica si una firma es válida para un hash dado"""
    try:
        clave_publica.verify(
            firma,
            hash_documento,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False

def obtener_sello_tiempo():
    """Devuelve un sello de tiempo en formato ISO"""
    return datetime.now(UTC).isoformat()

# ======= Simulación de Certificado Digital =======

def obtener_certificado(nombre, clave_publica):
    return {
        "nombre": nombre,
        "clave_publica_pem": clave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    }

# ======= Representación del Documento =======

class DocumentoContrato:
    """
    Representa un documento de contrato que puede ser firmado digitalmente por varias partes.

    Atributos:
        contenido (str): El texto o contenido principal del contrato.
        firmas (list): Lista de firmas digitales aplicadas al documento. Cada firma incluye:
            - firma (str): La firma digital en formato hexadecimal.
            - certificado (dict): Certificado digital del firmante.
            - sello_tiempo (str): Sello de tiempo en formato ISO cuando se realizó la firma.

    Métodos:
        insertar_firma(firma, certificado, sello_tiempo): Agrega una firma digital al documento.
        exportar(): Devuelve una representación JSON del documento y sus firmas.
    """
    def __init__(self, contenido):
        self.contenido = contenido
        self.firmas = []

    def insertar_firma(self, firma, certificado, sello_tiempo):
        self.firmas.append({
            "firma": firma.hex(),
            "certificado": certificado,
            "sello_tiempo": sello_tiempo
        })

    def exportar(self):
        return json.dumps({
            "contenido": self.contenido,
            "firmas": self.firmas
        }, indent=2)

# ======= Cifrado y Descifrado de Mensajes =======

def cifrar_mensaje(mensaje: str, clave_publica):
    """Cifra un mensaje y retorna el mensaje cifrado junto con el sello de tiempo."""
    sello_tiempo = obtener_sello_tiempo()
    mensaje_con_sello = f"{sello_tiempo}|{mensaje}"
    mensaje_cifrado = clave_publica.encrypt(
        mensaje_con_sello.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return mensaje_cifrado, sello_tiempo

def descifrar_mensaje(mensaje_cifrado: bytes, clave_privada, sello_tiempo_esperado: str):
    """Descifra un mensaje y verifica que el sello de tiempo coincida."""
    mensaje_descifrado = clave_privada.decrypt(
        mensaje_cifrado,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()
    sello_tiempo_recibido, mensaje = mensaje_descifrado.split("|", 1)
    if sello_tiempo_recibido == sello_tiempo_esperado:
        return mensaje
    else:
        return "Error: El sello de tiempo no coincide."

# ======= Flujo Principal =======
if __name__ == "__main__":
    # 1. Crear el contrato
    contrato = DocumentoContrato("Este es el contrato entre la Empresa XYZ y el Proveedor ABC.")

    # 2. Generar certificados y claves
    clave_priv_empresa, clave_pub_empresa = generar_claves()
    clave_priv_proveedor, clave_pub_proveedor = generar_claves()

    cert_empresa = obtener_certificado("Empresa XYZ", clave_pub_empresa)
    cert_proveedor = obtener_certificado("Proveedor ABC", clave_pub_proveedor)

    # 3. Firma de la empresa
    hash_doc = generar_hash(contrato.contenido)
    firma_empresa = firmar_documento(hash_doc, clave_priv_empresa)
    contrato.insertar_firma(firma_empresa, cert_empresa, obtener_sello_tiempo())

    # 4. Verificación por el proveedor
    verificacion = verificar_firma(hash_doc, firma_empresa, clave_pub_empresa)

    if verificacion:
        # 5. Firma del proveedor
        hash_doc_prov = generar_hash(contrato.contenido)
        firma_proveedor = firmar_documento(hash_doc_prov, clave_priv_proveedor)
        contrato.insertar_firma(firma_proveedor, cert_proveedor, obtener_sello_tiempo())
        print("Contrato firmado por ambas partes.\n")
    else:
        print("Firma de la empresa inválida. No se firma el contrato.")

    # 6. Exportar documento firmado
    print("Documento Final:\n")
    print(contrato.exportar())

    # 7. Envío de mensaje cifrado de la empresa al proveedor con sello de tiempo
    mensaje = "Hola Proveedor ABC, este es un mensaje confidencial."
    mensaje_cifrado, sello_tiempo_mensaje = cifrar_mensaje(mensaje, clave_pub_proveedor)
    print("\nMensaje cifrado enviado al proveedor (hex):")
    print(mensaje_cifrado.hex())
    print("Sello de tiempo del envío:", sello_tiempo_mensaje)

    # El proveedor descifra el mensaje y verifica el sello de tiempo
    mensaje_descifrado = descifrar_mensaje(mensaje_cifrado, clave_priv_proveedor, sello_tiempo_mensaje)
    print("\nMensaje descifrado por el proveedor:")
    print(mensaje_descifrado)
