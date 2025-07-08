# Steganography Web Application
(https://ciphernest-1-9dy3.onrender.com/)

This is a simple web application built with Flask that allows users to encode a secret message into an image (steganography) and decode a message from an image.

## Features

*   **Encode**: Hide a text message within a PNG image.
*   **Decode**: Extract a hidden message from a PNG image.
*   Strong AES-256 encryption (via PyCryptodome) with PBKDF2-SHA256 key derivation (unique salt per message, 100,000 iterations) used to protect messages, requiring an encryption key.
*   Image preview before upload.
*   User-friendly drag and drop interface for PNG image uploads.
*   Password strength meter for the encryption key, providing real-time feedback.
*   Loading overlay with spinner during processing, providing feedback during encoding/decoding operations.
*   Client-side message size estimation to check fit within the selected image before encoding.
*   Download of the encoded image.

## Project Structure

```
├── app.py                # Main Flask application
├── requirements.txt      # Python dependencies
├── static/
│   ├── css/
│   │   └── style.css     # CSS stylesheets
│   └── js/
│       └── main.js       # JavaScript for client-side interactions
├── templates/
│   ├── index.html        # Home page
│   ├── encode.html       # Page for encoding messages
│   └── decode.html       # Page for decoding messages
├── uploads/              # Directory for temporary image uploads (created automatically)
├── .gitignore            # Specifies intentionally untracked files that Git should ignore
├── vercel.json           # Vercel deployment configuration
└── README.md             # This file
```

## Setup and Installation

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd <repository-name>
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## How to Run

1.  **Ensure you are in the project's root directory and your virtual environment is activated.**

2.  **Run the Flask development server:**
    ```bash
    flask run
    ```
    Or, if you want to run in debug mode (as configured in `app.py`):
    ```bash
    python app.py
    ```

3.  **Open your web browser and go to:**
    ```
    http://127.0.0.1:5000/
    ```

## Usage

*   Navigate to the "Hide Message" page (was "Encode Message") to hide your message in an image.
*   Navigate to the "Reveal Message" page (was "Decode Message") to extract a message from an image.
*   Follow the on-screen instructions. Note that only PNG images are supported for encoding and decoding. An encryption key is required for both operations. Use the drag and drop area or the file input field to upload your image.

## Dependencies

The application relies on the following Python packages (see `requirements.txt` for specific versions):

*   Flask
*   gunicorn
*   numpy
*   opencv-python-headless
*   Pillow
*   pycryptodome

