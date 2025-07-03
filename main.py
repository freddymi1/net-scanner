import threading
import network as net
from webapp import app

def main():
    net.get_network_info()
    print(f"\nConfiguration détectée:")
    print(f"Interface: {net.NETWORK_INTERFACE}")
    print(f"Plage IP: {net.IP_RANGE}")
    net.arp_scan()
    threading.Thread(target=net.periodic_scan, daemon=True).start()
    threading.Thread(target=net.start_sniffing, daemon=True).start()
    print("\nServeur web démarré sur http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)

if __name__ == "__main__":
    main()