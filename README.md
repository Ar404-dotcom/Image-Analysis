# Image Analysis Workbench

This project now includes both:

- A CLI image converter for ASM, binary, and base64 output
- A malware-oriented scanner for suspicious ASM, image, and polyglot files
- A Streamlit frontend that wraps both workflows in a browser UI

## Features

### Converter

- Convert uploaded images into assembly `db` byte arrays
- Generate binary strings from RGB pixel bytes
- Export base64-encoded image content
- Resize by width before conversion

### Scanner

- Scan `.asm`, `.bin.txt`, and common image formats
- Detect suspicious syscalls, NOP slides, shellcode-like patterns, embedded payloads, and polyglot indicators
- Show aggregated risk score and severity breakdown
- Export structured JSON reports

## Setup

```bash
pip install -r requirements.txt
```

## Run The Frontend

```bash
streamlit run app.py
```

## CLI Usage

### Converter

```bash
python converter.py path/to/image.png --format asm
```

Arguments:

- `image_path`: Path to the input image
- `--format`: `asm`, `binary`, `string`, or `all`
- `--width`: Resize image to this width while preserving aspect ratio

### Scanner

```bash
python malware_scanner.py output/test_image.png.asm
python malware_scanner.py --scan-dir output/
```

## Test

```bash
python -m unittest tests/test_capstone_feature.py
```
