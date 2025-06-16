---
title: Break the Syntax CTF 2025 - Server Roulette
date: 2025-05-13
categories: [CTF]
tags: [CTF, crypto, hash, seed]
---
## Source Code

```python
from hashlib import sha256
import secrets


def get_color(number):
    """Determine roulette color for a given number"""
    if number == 0:
        return 'green'
    return 'red' if number % 2 == 1 else 'black'


def main():
    print("Welcome to Provably Fair Roulette!")

    with open('flag', 'rt') as f:
        FLAG = f.read()

    streak_13 = 0
    while True:
        # Generate server seed and its hash
        server_seed = sha256(bytes(secrets.randbits(17))).hexdigest()
        server_seed_hash = sha256(server_seed.encode()).hexdigest()

        print(f"Server seed hash (verify later): {server_seed_hash}")

        # Get client seed
        print("Enter your client seed (press enter to generate): ", end="")
        client_seed = input().strip()
        if not client_seed:
            client_seed = secrets.token_bytes(8).hex()
            print(f"Generated client seed: {client_seed}")

        # Generate game hash
        combined = f"{server_seed}:{client_seed}"
        game_hash = sha256(combined.encode()).hexdigest()
        hash_int = int(game_hash, 16)

        # Calculate roulette result
        roulette_number = hash_int % 37  # 0-36
        roulette_color = get_color(roulette_number)

        # Get user's bet
        while True:
            print("Place your bet (number 0-36 or color red/black/green): ", end="")
            bet = input().strip().lower()
            if bet in ['green', 'red', 'black']:
                break
            try:
                num = int(bet)
                if 0 <= num <= 36:
                    bet = str(num)  # Standardize to string for comparison
                    break
                print("Number must be between 0-36")
            except ValueError:
                print("Invalid bet. Enter number (0-36) or color (red/black/green)")

        # Determine result
        result_str = f"{roulette_number} ({roulette_color})"
        print(f"\nThe wheel lands on: {result_str}")

        # Check win conditions
        win = False
        if bet.isdigit():
            win = int(bet) == roulette_number
        else:
            win = bet == roulette_color

        if win:
            print("Congratulations! You win! ")
            if roulette_number == 13:
                print("...and you got 13, double congratulations!")
                streak_13 += 1
            else:
                print("But it's not 13, no streak for you")
                streak_13 = 0
        else:
            print("Sorry, you lose!")
            streak_13 = 0

        # Verification information
        print()
        print("Verification Details:")
        print(f"Server seed: {server_seed}")
        print(f"Client seed: {client_seed}")
        print(f"Combined string: {combined}")
        print(f"Game hash: {game_hash}")
        print(f"Calculated number: {roulette_number}")
        print(f"Resulting color: {roulette_color}")

        if streak_13 == 37:
            print("How? How is it possible? What was the chance?! "
                  f"Anyway, here's your flag, congratulations... {FLAG}")
            exit()


if __name__ == "__main__":
    main()

```

This code is hosted on a server that users connect to and input values.

### Code Analysis

Let's try to understand what the code is doing. First, the program will generate a `server_seed` by taking the sha256 hash of `bytes(secrets.randbits(17))`, which generates a byte array of an empty number of bytes from $0$ to $2^{17}-1$. The server will then generate `server_seed_hash` by taking the sha256 hash of the server seed.

The code will print the server seed hash, then request a client seed and then generate `combined = {server_seed}:{client_seed}`. Then, it hashes the combined seed, converts it to its decimal version `hash_int`, and finds its remainder modulo $37$.

The user inputs a bet on a number or color and the program compares it to the result calculated above. However, to find the flag, the user must input $13$ and get it right $37$ times in a row. If the user either bets incorrectly or bets correctly but doesn't bet $13$, the streak resets to $0$.

## Approach

Firstly, I noticed that there are only $2^{17}$ possible seeds, which is on the magnitude of $10^{5}$; sha256 is reproducible, meaning we can find the hash of each server seed, and more importantly, find a client seed for each server seed hash so that `hash_int % 37 == 13`.
### Finding Client Seeds

```python
from hashlib import sha256
import json

server_hash_db = {}

# Generate server seed and hash
for i in range(2 ** 17):
    server_seed = sha256(bytes(i)).hexdigest()
    server_seed_hash = sha256(server_seed.encode()).hexdigest()

	# Find corresponding client seed
    for j in range(1000):
        combined = f"{server_seed}:{j}"
        game_hash = sha256(combined.encode()).hexdigest()
        hash_int = int(game_hash, 16)
        if hash_int % 37 == 13:
            server_hash_db[server_seed_hash] = j
            break

with open("sol-server_seeds.json", "w") as f:
    json.dump(server_hash_db, f, indent=2)
```

Rather than dynamically finding each client seed after connecting to the server, I created a dictionary of all hashes and their corresponding client seeds. To generate the server seed and hash, I iterated through all $2^{17}$ possible byte arrays used the same method as the source code.

Then, to find the client seed, I iterated through values up to $999$ and checked if the combined seed worked. Unsurprisingly, the largest value of $j$ was less than $200$.

After running the code, we are left with the following `json` file.

```json
{
  "cd372fb85148700fa88095e3492d3f9f5beb43e555e5ff26d95f5a6adc36f8e6": 8,
  "bb7c53d34f6384244da5d41af9523beb234190b8209ec56dec7b7ecee341c300": 5,
  "d3181ef76c9daf05afba3c94ff4e341a834ee2854e36fbeb8388352d2fd23b35": 3,
  ...
}
```
### Connecting to the Server

I could've just used the database of server seed hashes and manually went through $37$ rounds of server roulette to find the flag, but I'm lazy and wanted to try connecting to the server with `python` via `pwntools`.

```python
from pwn import *
import json

# server seeds database
with open("sol-server_seeds.json", "r") as f:
    winning_seeds = json.load(f)

HOST = "localhost"
PORT = 1337

r = remote(HOST, PORT)

streak = 0

while True:
    try:
        # Read server seed hash
        r.recvuntil(b"Server seed hash (verify later): ")
        server_seed_hash = r.recvline().strip().decode()
        print(f"Server seed hash: {server_seed_hash}")

        # Send number from database
        client_seed = winning_seeds[server_seed_hash]
        print(f"Sending: {client_seed}")
        r.recvuntil(b"Enter your client seed (press enter to generate): ")
        r.sendline(str(client_seed).encode())

        # Send 13
        print(f"Sending: 13")
        r.recvuntil(b"Place your bet (number 0-36 or color red/black/green): ")
        r.sendline(b"13")
        
        # Check response
        response = r.recvuntil(b"Verification Details:").decode()
        streak += 1
        print(f"Win #{streak}")
        
        if streak == 37:
                print("Receiving final message:")
                final_output = r.recv().decode()
                print(final_output)
                r.close()
                break
```

The code first imports the `json` file, then after connecting to the server, the script will read the server seed hash. It will find the corresponding client seed to the hash and send it to the server. Then, it will send $13$, and read the result to ensure nothing went wrong.

After $37$ rounds, the server should send the flag!

## Final Result

After running both scripts, we get the following output.

```
[+] Opening connection to localhost on port 1337: Done
Server seed hash: fbee1b5973470403ba6505796e20d518c26576396433a7931f040aec0f00949e
Sending: 6
Sending: 13
Win #1
Server seed hash: 8b355c227c3eef280dadc4d7f3315bce32dc9a56e55f93d811f1b5786edfc84a
Sending: 29
Sending: 13
Win #2
...
Server seed hash: 189390e66b472d3cc900563f73e3052fb2616eeca69c0226d8d68c69b7e2c73c
Sending: 28
Sending: 13
Win #37
Receiving final message:

Server seed: ece3072155b4392939a7739c57cc307aac2dccef70eae1927b098a7a8c5fb81f
Client seed: 28
Combined string: ece3072155b4392939a7739c57cc307aac2dccef70eae1927b098a7a8c5fb81f:28
Game hash: abfc04810ff67c47736d18c2cf1d76f3f0842df4ee61fcbf01e256a6e10f5b31
Calculated number: 13
Resulting color: red
How? How is it possible? What was the chance?! Anyway, here's your flag, congratulations... FLAG

[*] Closed connection to localhost port 1337
```

We get our flag and we're done.
