#!/usr/bin/env python3
import os
import sys

def display_launcher():
    print("""
████████╗ █████╗ ██████╗  ██████╗ 
╚══██╔══╝██╔══██╗██╔══██╗██╔═══██╗
   ██║   ███████║██████╔╝██║   ██║
   ██║   ██╔══██║██╔══██╗██║   ██║
   ██║   ██║  ██║██║  ██║╚██████╔╝
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ 
                                    
    Taro Scanner Launcher
        Choose Your Scanner Version
        """)

def main():
    display_launcher()
    
    print("Available Scanner Versions:")
    print("[1] Taro Basic Scanner (v2.0)")
    print("[2] Taro Advanced Scanner (v3.0)")
    print("[0] Exit")
    
    while True:
        try:
            choice = input("\nSelect scanner version: ").strip()
            
            if choice == '0':
                print("\n[+] Goodbye!")
                sys.exit(0)
            elif choice == '1':
                if os.path.exists('taro_scanner.py'):
                    print("\n[*] Launching Taro Basic Scanner...")
                    os.system('python taro_scanner.py')
                    break
                else:
                    print("[-] Error: taro_scanner.py not found!")
            elif choice == '2':
                if os.path.exists('taro_advanced.py'):
                    print("\n[*] Launching Taro Advanced Scanner...")
                    os.system('python taro_advanced.py')
                    break
                else:
                    print("[-] Error: taro_advanced.py not found!")
            else:
                print("[-] Invalid choice. Please select 1, 2, or 0.")
                
        except KeyboardInterrupt:
            print("\n\n[!] Launcher interrupted by user")
            sys.exit(0)
        except Exception as e:
            print(f"\n[-] Error: {e}")

if __name__ == "__main__":
    main()
