# 🏢🤝🔒 Simulación de Firma Digital y Cifrado entre Empresa y Proveedor

Este proyecto es una **simulación** de un proceso de firma digital y cifrado de mensajes entre una **empresa** y un **proveedor**, utilizando la librería `cryptography` de Python. El objetivo es demostrar cómo se pueden proteger documentos y comunicaciones en un entorno digital, asegurando **autenticidad**, **integridad** y **confidencialidad**.

> ⚠️ **Nota:** Este trabajo está orientado principalmente a mostrar **cómo se lleva a cabo la solución e implementación** de un sistema de firma digital y cifrado, más que a su ejecución práctica. Es ideal para entender el procedimiento y los pasos criptográficos involucrados, no tanto para un uso productivo o automatizado.

## 🚀 ¿Qué hace este trabajo?

- **Genera claves públicas y privadas** para ambas partes (empresa y proveedor).
- **Crea un contrato digital** que puede ser firmado por ambas partes.
- **Firma digitalmente** el contrato usando las claves privadas y verifica la validez de las firmas con las claves públicas.
- **Adjunta certificados digitales simulados** a cada firma.
- **Cifra y descifra mensajes** entre la empresa y el proveedor, incluyendo un sello de tiempo para mayor seguridad.
- **Exporta el documento firmado** en formato JSON, mostrando todas las firmas y certificados.

## 🛡️ ¿Por qué es seguro?

El proyecto utiliza la librería `cryptography`, que implementa algoritmos criptográficos modernos y robustos, como:

- **RSA** para generación de claves, firma digital y cifrado asimétrico.
- **SHA-256** para la generación de hashes seguros.
- **Padding OAEP y PSS** para proteger contra ataques criptográficos conocidos.
- **Sello de tiempo** para evitar ataques de repetición y garantizar la validez temporal de las firmas y mensajes.

Estas herramientas permiten simular un sistema real de protección de documentos y comunicaciones, como los que se usan en sistemas de **PKI (Infraestructura de Clave Pública)** en la vida real.

## 📦 Estructura del código

- **PKI.py**: Contiene toda la lógica de generación de claves, firma, verificación, cifrado, descifrado y manejo de certificados y documentos.
- **README.md**: Este archivo, con la explicación del proyecto.

## 📝 Ejemplo de uso

Al ejecutar el script, verás cómo:
1. Se crea un contrato.
2. La empresa lo firma digitalmente.
3. El proveedor verifica la firma y, si es válida, también firma el contrato.
4. Se exporta el contrato firmado por ambas partes.
5. Se envía un mensaje cifrado de la empresa al proveedor, que solo el proveedor puede descifrar.

## 📚 Requisitos

- Python 3.8+
- Instalar la librería `cryptography`:
