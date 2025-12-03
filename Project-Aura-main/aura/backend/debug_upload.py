import requests
import os
import sys

# Use the file we found earlier
PCAP_PATH = r"c:\Users\Dell\Downloads\Project-Aura-main\Project-Aura-main\aura\backend\small_test.pcap"
URL = "http://localhost:8000/api/upload-capture/"

def test_upload():
    print(f"Checking file: {PCAP_PATH}")
    if not os.path.exists(PCAP_PATH):
        print(f"❌ File not found!")
        return

    print(f"File size: {os.path.getsize(PCAP_PATH)} bytes")
    print(f"🚀 Sending POST request to {URL}...")
    
    try:
        with open(PCAP_PATH, 'rb') as f:
            files = {'file': f}
            # Set a timeout to avoid hanging forever
            response = requests.post(URL, files=files, timeout=300)
        
        print(f"Response Status: {response.status_code}")
        print(f"Response Body: {response.text}")

    except Exception as e:
        print(f"❌ Request failed: {e}")

if __name__ == "__main__":
    test_upload()
