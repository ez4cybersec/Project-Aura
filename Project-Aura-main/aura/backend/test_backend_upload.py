import requests
import os

# Path to the PCAP file we found earlier
PCAP_PATH = r"c:\Users\Dell\Downloads\Project-Aura-main\Project-Aura-main\aura\backend\uploads\2a363aad-08c8-4fea-bcfd-9461c32e2780.pcap"
URL = "http://localhost:8000/api/upload-capture/"

def test_upload():
    if not os.path.exists(PCAP_PATH):
        print(f"❌ PCAP file not found at: {PCAP_PATH}")
        return

    print(f"🚀 Uploading {PCAP_PATH} to {URL}...")
    
    try:
        with open(PCAP_PATH, 'rb') as f:
            files = {'file': f}
            response = requests.post(URL, files=files)
        
        print(f"Response Code: {response.status_code}")
        print(f"Response Body: {response.text}")
        
        if response.status_code == 200:
            print("\n✅ Upload Successful! Check your BACKEND TERMINAL for the analysis logs.")
        else:
            print("\n❌ Upload Failed.")

    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    test_upload()
