# Image Analysis & Converter

A Python tool to convert images into various formats suitable for low-level programming and embedding.

## Features

Converts any input image into:

1.  **ASM**: Assembly `db` byte arrays.
2.  **Binary**: A continuous string of bits (0s and 1s).
3.  **Base64**: Standard Base64 encoded string.

## Setup

1.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

```bash
python converter.py path/to/image.png --format asm
```

### Arguments

- `image_path`: Path to the input image.
- `--format`: Output format. Options: `asm`, `binary`, `string` (base64), `all` (default).
- `--width`: Resize image to this width (optional, maintains aspect ratio).
