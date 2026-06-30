import requests

def check_website(url):
    print(f"\n--- Scanning {url} ---")
    try:
        # 1. The Network Monitor (What we did last time)
        response = requests.get(url, timeout=5)
        print(f"✅ Network: Online (Status Code: {response.status_code})")

        # 2. The Vulnerability Assessment (The NEW stuff!)
        print("\n🔍 Checking Security Headers...")
        
        # A list of standard security locks every website should have
        security_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options'
        ]

        # Loop through our list and check if the website has them
        for header in security_headers:
            if header in response.headers:
                print(f"🔒 PASS: {header} is active.")
            else:
                print(f"⚠️ WARNING: {header} is MISSING!")

    except Exception as e:
        print(f"❌ Offline or Unreachable! Error: {e}")

# Let's test it out! 
check_website("https://google.com")