# Image Analysis Workbench

This project now includes both:

- A CLI image converter for ASM, binary, and base64 output
- A malware-oriented scanner for suspicious ASM, image, and polyglot files
- A file reputation checker for hashes, Windows signatures, and optional online lookup
- A Windows-only live behavior monitor for anti-injection and anti-exploitation signals
- Live TCP/UDP port checking for listeners and active remote connections
- A controlled file-lock threat simulator with one-click containment and restore
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

### File Reputation

- Calculate MD5, SHA-1, and SHA-256 for uploaded files
- Check Windows Authenticode signature status when available
- Query VirusTotal by SHA-256 hash when `VIRUSTOTAL_API_KEY` is configured or entered in the UI
- Run an offline clean-file demo without sending any network request
- Export reputation reports as JSON

### Live Monitoring

- Run bounded Windows user-mode monitoring sessions from the frontend
- Watch process starts, suspicious parent-child chains, and process masquerading
- Inspect new thread start addresses for private executable-memory starts
- Track newly observed private executable-memory regions in sensitive processes
- Watch suspicious executable regions for sleep-obfuscation style page-protection flips
- Check live TCP/UDP ports, exposed listeners, and public remote-control or file-transfer connections
- Run the controlled target-file demo: rename `C:\Users\HP\Downloads\Resume updated June.pdf` to `Resume updated June_LOCKED.pdf`, record previous/current names in `output/readme.txt`, raise a HIGH alert with score 90, then contain the simulator and restore the original name
- Export monitoring reports as JSON

## Setup

```bash
pip install -r requirements.txt
```

Optional online reputation lookup:

```bash
set VIRUSTOTAL_API_KEY=your_api_key_here
```

## Run The Frontend

```bash
streamlit run app.py
```

The `Live Monitoring` tab is Windows-only. It uses a separate `live_monitor` package and does not depend on the static image scanner or converter modules.

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
python -m unittest tests/test_live_monitor_rules.py
```
