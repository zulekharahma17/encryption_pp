from flask import Flask, render_template, request, session
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Ganti dengan kunci rahasia Anda

# Fungsi untuk enkripsi menggunakan AES
def encrypt_aes(plain_text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')  # Encode IV ke base64
    ct = base64.b64encode(ct_bytes).decode('utf-8')  # Encode ciphertext ke base64
    return iv, ct

# Fungsi untuk dekripsi menggunakan AES
def decrypt_aes(iv, cipher_text, key):
    iv = base64.b64decode(iv)  # Decode IV dari base64
    ct = base64.b64decode(cipher_text)  # Decode ciphertext dari base64
    cipher = AES.new(key, AES.MODE_CBC, iv)  # Inisialisasi cipher dengan IV
    pt = unpad(cipher.decrypt(ct), AES.block_size)  # Hapus padding
    return pt.decode('utf-8')

# Fungsi untuk enkripsi menggunakan DES
def encrypt_des(plain_text, key):
    cipher = DES.new(key, DES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plain_text.encode(), DES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')  # Encode IV ke base64
    ct = base64.b64encode(ct_bytes).decode('utf-8')  # Encode ciphertext ke base64
    return iv, ct

# Fungsi untuk dekripsi menggunakan DES
def decrypt_des(iv, cipher_text, key):
    iv = base64.b64decode(iv)  # Decode IV dari base64
    ct = base64.b64decode(cipher_text)  # Decode ciphertext dari base64
    cipher = DES.new(key, DES.MODE_CBC, iv)  # Inisialisasi cipher dengan IV
    pt = unpad(cipher.decrypt(ct), DES.block_size)  # Hapus padding
    return pt.decode('utf-8')

# Fungsi untuk enkripsi menggunakan Fernet
def encrypt_fernet(plain_text):
    key = Fernet.generate_key()  # Generate key for Fernet
    cipher = Fernet(key)
    cipher_text = cipher.encrypt(plain_text.encode())
    return base64.b64encode(key).decode('utf-8'), base64.b64encode(cipher_text).decode('utf-8')

# Fungsi untuk dekripsi menggunakan Fernet
def decrypt_fernet(cipher_text, key):
    cipher = Fernet(base64.b64decode(key))
    decrypted_text = cipher.decrypt(base64.b64decode(cipher_text))
    return decrypted_text.decode('utf-8')

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'encrypt' in request.form:
            plain_text = request.form['plain_text']
            algorithm = request.form['algorithm']

            if algorithm == 'AES':
                # Enkripsi AES
                key = get_random_bytes(16)  # Menghasilkan kunci AES 16 bytes
                session['aes_key'] = base64.b64encode(key).decode('utf-8')  # Simpan kunci dalam session
                iv, cipher_text = encrypt_aes(plain_text, key)
                return render_template('index.html', cipher_text=cipher_text, iv=iv, algorithm=algorithm)

            elif algorithm == 'DES':
                # Enkripsi DES
                key = get_random_bytes(8)  # Menghasilkan kunci DES 8 bytes
                session['des_key'] = base64.b64encode(key).decode('utf-8')  # Simpan kunci dalam session
                iv, cipher_text = encrypt_des(plain_text, key)
                return render_template('index.html', cipher_text=cipher_text, iv=iv, algorithm=algorithm)

            elif algorithm == 'Fernet':
                # Enkripsi Fernet
                key, cipher_text = encrypt_fernet(plain_text)
                session['fernet_key'] = key
                return render_template('index.html', cipher_text=cipher_text, key=key, algorithm=algorithm)

        if 'decrypt' in request.form:
            cipher_text = request.form['cipher_text']
            iv = request.form['iv']  # Ambil IV dari input
            algorithm = request.form['algorithm']

            if algorithm == 'AES':
                # Dekripsi AES
                key = base64.b64decode(session.get('aes_key'))  # Ambil kunci dari session
                decrypted_text = decrypt_aes(iv, cipher_text, key)
                return render_template('index.html', decrypted_text=decrypted_text, algorithm=algorithm)

            elif algorithm == 'DES':
                # Dekripsi DES
                key = base64.b64decode(session.get('des_key'))  # Ambil kunci dari session
                decrypted_text = decrypt_des(iv, cipher_text, key)
                return render_template('index.html', decrypted_text=decrypted_text, algorithm=algorithm)

            elif algorithm == 'Fernet':
                # Dekripsi Fernet
                key = session.get('fernet_key')
                decrypted_text = decrypt_fernet(cipher_text, key)
                return render_template('index.html', decrypted_text=decrypted_text, algorithm=algorithm)

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
