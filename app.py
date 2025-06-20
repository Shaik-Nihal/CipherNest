from flask import Flask, render_template, request, send_from_directory, jsonify, send_file, after_this_request
import os
import cv2
import numpy as np
import base64
from werkzeug.utils import secure_filename
from PIL import Image # Keep for potential validation

# Imports for AES encryption & PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2 # Added for PBKDF2

app = Flask(__name__)
UPLOAD_FOLDER = '/tmp/stego_uploads' # Changed for Vercel compatibility
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ALLOWED_EXTENSIONS'] = {'png'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # 16MB max upload size

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- Cryptographic Constants ---
AES_KEY_SIZE = 32  # 256 bits for AES
AES_BLOCK_SIZE = AES.block_size # 16 bytes for AES
SALT_SIZE = 16 # 16 bytes for salt
PBKDF2_ITERATIONS = 100000 # Recommended minimum is 100,000, can be higher.

# --- AES Encryption Function (with PBKDF2) ---
def aes_encrypt(plaintext: str, password: str) -> bytes:
    if not password:
        raise ValueError("Encryption key (password) cannot be empty.")
    
    plaintext_bytes = plaintext.encode('utf-8')
    
    # 1. Generate a cryptographically secure random salt
    salt = get_random_bytes(SALT_SIZE)
    
    # 2. Derive the encryption key using PBKDF2
    #    Using SHA256 as the HMAC hash module for PBKDF2
    key = PBKDF2(password.encode('utf-8'), salt, dkLen=AES_KEY_SIZE, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)
    
    # 3. Generate a random IV (Initialization Vector)
    iv = get_random_bytes(AES_BLOCK_SIZE)
    
    # 4. Encrypt using AES (CBC mode)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext_bytes, AES_BLOCK_SIZE, style='pkcs7')
    ciphertext = cipher.encrypt(padded_plaintext)
    
    # 5. Return salt + iv + ciphertext
    return salt + iv + ciphertext

# --- AES Decryption Function (with PBKDF2) ---
def aes_decrypt(data_blob: bytes, password: str) -> str:
    if not password:
        raise ValueError("Decryption key (password) cannot be empty.")

    # 1. Extract salt, IV, and ciphertext from the data_blob
    #    Ensure data_blob is long enough for salt and IV
    if len(data_blob) < SALT_SIZE + AES_BLOCK_SIZE:
        raise ValueError("Invalid encrypted data: too short to contain salt and IV.")
        
    salt = data_blob[:SALT_SIZE]
    iv = data_blob[SALT_SIZE : SALT_SIZE + AES_BLOCK_SIZE]
    ciphertext = data_blob[SALT_SIZE + AES_BLOCK_SIZE:]
    
    # 2. Derive the decryption key using PBKDF2 with the extracted salt
    key = PBKDF2(password.encode('utf-8'), salt, dkLen=AES_KEY_SIZE, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)
    
    # 3. Decrypt using AES (CBC mode)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    try:
        decrypted_padded_plaintext = cipher.decrypt(ciphertext)
        original_plaintext_bytes = unpad(decrypted_padded_plaintext, AES_BLOCK_SIZE, style='pkcs7')
        return original_plaintext_bytes.decode('utf-8')
    except (ValueError, KeyError) as e:
        # ValueError can be raised by unpad if padding is incorrect (often due to wrong key)
        # KeyError might occur with certain unpadding errors or corrupted data structures.
        app.logger.error(f"AES decryption failed (likely wrong key or corrupted data): {e}")
        raise ValueError("Decryption failed. This could be due to an incorrect key or corrupted data.")


# --- Helper Bit/Byte Functions (remain the same) ---
def str_to_bits(s_chars_ords):
    return [int(b) for char_val in s_chars_ords for b in format(char_val, '08b')]

def bits_to_bytes(bits):
    return [int(''.join(str(bit) for bit in bits[i:i+8]), 2) for i in range(0, len(bits), 8)]

# --- Image Encoding Function (uses new AES logic) ---
def encode_image_logic(image_path, message, key_password, output_path):
    try:
        img = cv2.imread(image_path)
        if img is None:
            raise ValueError("Image not found or could not be read. Ensure it's a valid image file.")
        
        flat = img.flatten()

        # Encrypt using AES; result is salt + iv + ciphertext (bytes)
        encrypted_data_bytes = aes_encrypt(message, key_password)
        
        # Base64 encode these bytes
        b64_encoded_encrypted_data_str = base64.b64encode(encrypted_data_bytes).decode('utf-8')
        
        bits = str_to_bits([ord(ch) for ch in b64_encoded_encrypted_data_str])

        length = len(bits)
        len_bits = list(map(int, format(length, '032b')))
        all_bits = len_bits + bits

        if len(all_bits) > len(flat):
            required_bits = len(all_bits)
            available_pixels = len(flat)
            raise ValueError(f"Image too small to hold this message! Message (incl. salt/IV) requires {required_bits} bits, image has space for {available_pixels} bits.")

        for i, bit in enumerate(all_bits):
            flat[i] = (flat[i] & 0xFE) | bit

        encoded_img = flat.reshape(img.shape)
        cv2.imwrite(output_path, encoded_img)
        return True
    except ValueError as ve:
        app.logger.error(f"ValueError in encode_image_logic: {ve}")
        raise ve
    except Exception as e:
        app.logger.error(f"Generic error in encode_image_logic: {e}", exc_info=True)
        raise Exception(f"An unexpected error occurred during image encoding: {str(e)}")

# --- Image Decoding Function (uses new AES logic) ---
def decode_image_logic(image_path, key_password):
    try:
        img = cv2.imread(image_path)
        if img is None:
            raise ValueError("Image not found or could not be read. Ensure it's a valid image file.")

        flat = img.flatten()
        if len(flat) < 32:
            raise ValueError("Image is too small (cannot read length header).")

        len_bits = [flat[i] & 1 for i in range(32)]
        msg_len_in_bits = int(''.join(str(b) for b in len_bits), 2)

        if (32 + msg_len_in_bits) > len(flat):
            raise ValueError("Corrupted image: Message length in header exceeds image size.")

        data_bits = [flat[i] & 1 for i in range(32, 32 + msg_len_in_bits)]
        if len(data_bits) % 8 != 0:
             raise ValueError(f"Data corruption: Extracted bit length ({len(data_bits)}) for Base64 data is not a multiple of 8.")

        byte_vals = bits_to_bytes(data_bits)
        b64_encoded_encrypted_data_str = ''.join(chr(b) for b in byte_vals)
        
        try:
            # Decode Base64 to get salt + iv + ciphertext (bytes)
            salt_iv_plus_ciphertext = base64.b64decode(b64_encoded_encrypted_data_str)
        except base64.binascii.Error as b64e:
            app.logger.error(f"Base64 decoding failed: {b64e}")
            raise ValueError(f"Base64 decoding failed: {b64e}. Data may be corrupted.")

        decrypted_message = aes_decrypt(salt_iv_plus_ciphertext, key_password)
        return decrypted_message
        
    except ValueError as ve:
        app.logger.error(f"ValueError in decode_image_logic: {ve}")
        raise ve
    except Exception as e:
        app.logger.error(f"Generic error in decode_image_logic: {e}", exc_info=True)
        raise Exception(f"An unexpected error occurred during image decoding: {str(e)}")


# --- Flask Routes (largely unchanged, but pass 'key' as key_password) ---
def allowed_file(filename):
    return '.' in filename and            filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encode_page')
def encode_page_route():
    return render_template('encode.html')

@app.route('/decode_page')
def decode_page_route():
    return render_template('decode.html')

@app.route('/api/encode', methods=['POST'])
def api_encode_route():
    original_image_path = None
    encoded_image_path = None
    response_sent = False

    if 'image' not in request.files: return jsonify({"error": "No image file provided."}), 400
    file = request.files['image']
    message = request.form.get('message')
    key_password = request.form.get('key') # Renamed for clarity

    if not message: return jsonify({"error": "No message provided."}), 400
    if not key_password: return jsonify({"error": "No key provided."}), 400
    if file.filename == '': return jsonify({"error": "No image selected."}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        base, ext = os.path.splitext(filename)
        original_image_filename_server = f"{base}_{os.urandom(4).hex()}_orig{ext}"
        original_image_path = os.path.join(app.config['UPLOAD_FOLDER'], original_image_filename_server)
        encoded_image_filename_server = f"{base}_{os.urandom(4).hex()}_encoded{ext}"
        encoded_image_path = os.path.join(app.config['UPLOAD_FOLDER'], encoded_image_filename_server)
        download_display_name = f"{base}_encoded{ext}"

        try:
            file.save(original_image_path)
            encode_image_logic(original_image_path, message, key_password, encoded_image_path)
            
            @after_this_request
            def cleanup_encoded_image(response):
                try:
                    if os.path.exists(encoded_image_path): os.remove(encoded_image_path)
                except Exception as e:
                    app.logger.error(f"Error removing server-side encoded file {encoded_image_path}: {e}")
                return response
            
            response_sent = True
            return send_file(encoded_image_path, as_attachment=True, download_name=download_display_name)
        except ValueError as ve:
            app.logger.warning(f"Encoding failed (ValueError): {str(ve)}")
            return jsonify({"error": str(ve)}), 400
        except Exception as e:
            app.logger.error(f"Encoding failed (Exception): {str(e)}", exc_info=True)
            return jsonify({"error": f"Encoding process failed: {str(e)}"}), 500
        finally:
            if original_image_path and os.path.exists(original_image_path): os.remove(original_image_path)
            if not response_sent and encoded_image_path and os.path.exists(encoded_image_path): os.remove(encoded_image_path)
    else:
        return jsonify({"error": "Invalid file type. Only PNG images are allowed."}), 400

@app.route('/api/decode', methods=['POST'])
def api_decode_route():
    uploaded_image_path = None

    if 'image' not in request.files: return jsonify({"error": "No image file provided."}), 400
    file = request.files['image']
    key_password = request.form.get('key') # Renamed for clarity

    if not key_password: return jsonify({"error": "No key provided."}), 400
    if file.filename == '': return jsonify({"error": "No image selected."}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        base, ext = os.path.splitext(filename)
        temp_uploaded_filename_server = f"{base}_{os.urandom(4).hex()}_decode_target{ext}"
        uploaded_image_path = os.path.join(app.config['UPLOAD_FOLDER'], temp_uploaded_filename_server)
        
        try:
            file.save(uploaded_image_path)
            decoded_message = decode_image_logic(uploaded_image_path, key_password)
            return jsonify({"message": decoded_message})
        except ValueError as ve:
            app.logger.warning(f"Decoding failed (ValueError): {str(ve)}")
            return jsonify({"error": str(ve)}), 400
        except Exception as e:
            app.logger.error(f"Decoding failed (Exception): {str(e)}", exc_info=True)
            return jsonify({"error": f"Decoding process failed: {str(e)}"}), 500
        finally:
            if uploaded_image_path and os.path.exists(uploaded_image_path): os.remove(uploaded_image_path)
    else:
        return jsonify({"error": "Invalid file type. Only PNG images are allowed."}), 400

if __name__ == '__main__':
    app.run(debug=True, port=5000)
