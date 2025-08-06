#!/usr/bin/env python3
"""
ProtectIT Test Script
Creates sample files to test the malware scanner functionality
"""

import os
import hashlib
from pathlib import Path

def create_test_files():
    """Create test files with various risk levels"""
    
    # Create test directory
    test_dir = Path("test_files")
    test_dir.mkdir(exist_ok=True)
    
    # 1. Suspicious executable (simulated)
    suspicious_exe = test_dir / "suspicious.exe" 
    with open(suspicious_exe, 'wb') as f:
        # Write some suspicious-looking content
        f.write(b'This is a test file with suspicious patterns\n')
        f.write(b'CreateProcess\n')
        f.write(b'WriteProcessMemory\n')
        f.write(b'cmd.exe /c del /f *.*\n')
    
    # 2. Script file with suspicious content
    suspicious_script = test_dir / "malicious.vbs"
    with open(suspicious_script, 'w') as f:
        f.write('''
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "cmd.exe /c echo This is a test", 0, False
''')
    
    # 3. Normal text file (should be safe)
    normal_file = test_dir / "readme.txt"
    with open(normal_file, 'w') as f:
        f.write("This is a normal text file that should not trigger any alerts.")
    
    # 4. Batch file (potentially suspicious)
    batch_file = test_dir / "script.bat"
    with open(batch_file, 'w') as f:
        f.write('@echo off\necho Hello World\npause\n')
    
    # 5. Create a file with known malicious hash (for demo)
    demo_malware = test_dir / "demo_threat.bin"
    with open(demo_malware, 'wb') as f:
        # Create content that will hash to our demo threat hash
        content = b'a' * 1000  # Simple content
        f.write(content)
    
    print(f"✅ Created test files in {test_dir}/")
    print("Files created:")
    for file_path in test_dir.iterdir():
        if file_path.is_file():
            file_size = file_path.stat().st_size
            print(f"  📄 {file_path.name} ({file_size} bytes)")
    
    print("\n🧪 You can now test the scanner by scanning the 'test_files' directory!")
    print("Expected results:")
    print("  🔴 suspicious.exe - HIGH risk (suspicious API calls)")
    print("  🟡 malicious.vbs - MEDIUM risk (script file)")
    print("  🟡 script.bat - MEDIUM risk (batch file)")
    print("  🔵 demo_threat.bin - MEDIUM risk (suspicious extension pattern)")
    print("  🟢 readme.txt - Should be clean")

if __name__ == "__main__":
    create_test_files()
