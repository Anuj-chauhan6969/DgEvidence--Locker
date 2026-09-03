import bcrypt
h = '$2b$12$c5i8oxHruC/kpO0m7yOrmulYeG9uIuKtdpYDAuXL0ZvQI8.ryDPe6'
candidates = ['black', 'blue', 'green', 'red', 'white', 'yellow', 'favorite color']
for c in candidates:
    if bcrypt.checkpw(c.encode(), h.encode()):
        print(f"MATCH FOUND: '{c}'")
        exit(0)
print("No match found for candidates.")
