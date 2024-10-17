import socket
import argparse
import sys
import re

def parse_ssh_banner(response):
    """Extract OpenSSH version using regex."""
    try:
        # Use regex to match OpenSSH version in the banner
        match = re.search(r"OpenSSH_(\d+)\.(\d+)", response)
        if match:
            major, minor = int(match.group(1)), int(match.group(2))
            version_number = f"{major}.{minor}"
            print(f"[+] OpenSSH Version Detected: {version_number}")

            # Check if the version is vulnerable (below 9.3)
            if (major < 9) or (major == 9 and minor < 3):
                print(f"[!] Vulnerable OpenSSH version detected: {version_number}")
            else:
                print("[+] SSH version is not vulnerable.")
        else:
            print("[!] OpenSSH version not found in the banner.")
    except Exception as e:
        print(f"[!] Error parsing SSH banner: {e}")

def check_vulnerability(target, port):
    """Connect to the target and retrieve SSH banner."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)

        print(f"[+] Connecting to {target}:{port}...")
        sock.connect((target, port))

        # Send initial SSH handshake message
        sock.sendall(b"SSH-2.0-Client_Test\r\n")

        # Receive SSH banner response
        response = sock.recv(1024).decode('utf-8').strip()
        print(f"[+] Received banner: {response}")

        # Parse the SSH banner for vulnerability
        parse_ssh_banner(response)

    except socket.timeout:
        print("[!] Connection timed out.")
    except socket.error as e:
        print(f"[!] Socket error: {e}")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
    finally:
        sock.close()

def main():
    parser = argparse.ArgumentParser(description="CVE-2023-38408 Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP or URL")
    parser.add_argument("-p", "--port", type=int, default=22, help="Target port (default: 22)")

    args = parser.parse_args()
    check_vulnerability(args.target, args.port)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan aborted.")
        sys.exit(0)
