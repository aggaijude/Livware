import os
import shutil
import subprocess
import sys
try:
    from PIL import Image
except ImportError:
    print("Installing Pillow to convert the logo...")
    subprocess.run([sys.executable, "-m", "pip", "install", "pillow"], check=True)
    from PIL import Image

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def main():
    print("="*60)
    print(" 🚀 Livware Antivirus - Professional Build Script")
    print("="*60)
    
    # 1. Convert logo.png => logo.ico
    png_path = os.path.join(BASE_DIR, "logo.png")
    ico_path = os.path.join(BASE_DIR, "logo.ico")
    
    if os.path.exists(png_path):
        print("[1/3] Converting logo.png to logo.ico...")
        try:
            img = Image.open(png_path)
            # Use appropriate sizes for Windows icons
            img.save(ico_path, format="ICO", sizes=[(256, 256), (128, 128), (64, 64), (32, 32), (16, 16)])
            print("      ✓ Logo successfully converted.")
        except Exception as e:
            print(f"      ❌ Failed to convert logo: {e}")
            ico_path = None
    else:
        print("[1/3] logo.png not found! Using default executable icon.")
        ico_path = None
        
    print("[2/3] Configuring PyInstaller build...")
    # 2. Setup PyInstaller arguments
    # We use directory mode (no --onefile) because Large ML dependencies like LightGBM, 
    # numpy, and pefile are very slow to unpack to temp storage on every single launch. 
    # Instead, building it into a unified directory is the standard professional approach.
    pyi_args = [
        sys.executable, "-m", "PyInstaller",
        "--name", "Livware",
        "-y",                        # Auto overwrite dist directory
        "--noconsole",               # Professional: no background terminal window
        "--windowed",
        "--hidden-import", "lightgbm",  # Fixes ML unavailable
        "--hidden-import", "sklearn",   # Robust ML support
        "--hidden-import", "pefile",    # Fixes Sandbox parsing
        "--hidden-import", "yara",      # Fixes YARA matching
        "--add-data", f"models;models",
        "--add-data", f"rules;rules",
    ]
    
    if os.path.exists(png_path):
        pyi_args.extend(["--add-data", f"logo.png;."])
        
    if ico_path and os.path.exists(ico_path):
        pyi_args.extend(["--icon", "logo.ico"])
        
    # App entry point
    pyi_args.append("main.py")

    print("[3/3] Running PyInstaller (this involves tracing and packaging all dependencies)...")
    print(f"      Command: {' '.join(pyi_args)}")
    
    # Clean previous builds to prevent leftover junk
    for folder in ["build", "dist"]:
        path = os.path.join(BASE_DIR, folder)
        if os.path.exists(path):
            print(f"      Cleaning previous {folder} directory...")
            shutil.rmtree(path, ignore_errors=True)
            
    # Run the build
    subprocess.run(pyi_args, check=True)
    
    print("="*60)
    print(" ✅ Build Process Completed!")
    print(r"    Your executable is ready at: dist\Livware\Livware.exe")
    print("="*60)

if __name__ == "__main__":
    main()
