from passlib.hash import des_crypt
import time
import subprocess

# Step 1: Input password
password = input("Enter password to hash and crack: ")

# Step 2: Hash with DES crypt (John-compatible)
hashed = des_crypt.hash(password)

# Step 3: Save to file in JtR format
with open("crackme.txt", "w") as f:
    f.write(f"user:{hashed}\n")

print(f"[+] Hashed password saved to crackme.txt: {hashed}")

# Step 4: Time John the Ripper
start = time.time()

# Update this path to your JtR location
john_path = r"C:\Users\Geovanni\Downloads\John\john-1.9.0-jumbo-1-win64\run\john.exe"
subprocess.run([john_path, "crackme.txt"])

end = time.time()

# Step 5: Show cracked password
output = subprocess.check_output([john_path, "--show", "crackme.txt"]).decode()
print("\n[+] Cracked password:")
print(output)

# Step 6: Show crack time
print(f"\n[+] Time taken to crack: {end - start:.2f} seconds")
