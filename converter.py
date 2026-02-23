import argparse
import base64
from PIL import Image
import io
import sys

def image_to_binary_string(img):
    """Converts image bytes to a string of 0s and 1s."""
    # Convert image to RGB to ensure consistent byte structure
    img = img.convert('RGB')
    img_bytes = img.tobytes()
    binary_string = ''.join(format(byte, '08b') for byte in img_bytes)
    return binary_string

def image_to_asm(img):
    """Converts image bytes to an Assembly db array."""
    img = img.convert('RGB')
    img_bytes = img.tobytes()
    # Create lines of 16 bytes for readability
    lines = []
    chunk_size = 16
    for i in range(0, len(img_bytes), chunk_size):
        chunk = img_bytes[i:i + chunk_size]
        hex_values = ', '.join(f'0x{byte:02x}' for byte in chunk)
        lines.append(f'db {hex_values}')
    return '\n'.join(lines)

def image_to_base64(img):
    """Converts image to a base64 string."""
    buffered = io.BytesIO()
    # Save as PNG to the buffer to keep valid image format for base64
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")
    return img_str

def main():
    parser = argparse.ArgumentParser(description='Convert image to ASM, Binary, or Base64 String.')
    parser.add_argument('image_path', help='Path to the input image file')
    parser.add_argument('--format', choices=['asm', 'binary', 'string', 'all'], default='all', help='Output format')
    parser.add_argument('--width', type=int, help='Resize image to this width before processing')
    
    args = parser.parse_args()
    
    try:
        with Image.open(args.image_path) as img:
            print(f"Loaded image: {args.image_path} ({img.size[0]}x{img.size[1]})")
            
            if args.width:
                w_percent = (args.width / float(img.size[0]))
                h_size = int((float(img.size[1]) * float(w_percent)))
                img = img.resize((args.width, h_size), Image.Resampling.LANCZOS)
                print(f"Resized to: {img.size[0]}x{img.size[1]}")

            # Create output directory if it doesn't exist
            import os
            output_dir = "output"
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            
            base_name = os.path.basename(args.image_path)

            if args.format in ['asm', 'all']:
                print("\n--- ASM (db array start) ---")
                print(image_to_asm(img)[:500] + "\n... (truncated for display)")
                output_path = os.path.join(output_dir, base_name + ".asm")
                with open(output_path, "w") as f:
                    f.write(image_to_asm(img))
                print(f"Saved ASM to {output_path}")

            if args.format in ['binary', 'all']:
                print("\n--- Binary String (start) ---")
                bin_str = image_to_binary_string(img)
                print(bin_str[:100] + "...")
                output_path = os.path.join(output_dir, base_name + ".bin.txt")
                with open(output_path, "w") as f:
                    f.write(bin_str)
                print(f"Saved Binary String to {output_path}")

            if args.format in ['string', 'all']:
                print("\n--- Base64 String (start) ---")
                b64_str = image_to_base64(img)
                print(b64_str[:100] + "...")
                output_path = os.path.join(output_dir, base_name + ".b64.txt")
                with open(output_path, "w") as f:
                    f.write(b64_str)
                print(f"Saved Base64 String to {output_path}")

    except FileNotFoundError:
        print(f"Error: File not found at {args.image_path}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
