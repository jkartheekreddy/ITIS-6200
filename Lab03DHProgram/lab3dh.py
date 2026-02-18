import hashlib
import secrets
import os

# --- UI HELPER FUNCTIONS ---
def print_header(text):
    print(f"\n{'='*60}\n{text.center(60)}\n{'='*60}")

def print_step(text):
    print(f"\n[STEP] {text}")

def print_info(label, value):
    val_str = str(value)
    if len(val_str) > 40:
        print(f"{label}: {val_str[:20]} ... {val_str[-15:]}")
    else:
        print(f"{label}: {val_str}")

def truncate(val, start=20, end=15):
    s = str(val)
    if len(s) > start + end + 5:
        return f"{s[:start]} ... {s[-end:]}"
    return s


# --- Define Diffie-Hellman Constants G and P ---

P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)

G = 2


# --- PART A: STATEFUL PRNG ---

class SecurePRNG:
    def __init__(self, seed_int):
        self.state = hashlib.sha256(str(seed_int).encode()).digest()

    def generate(self, n_bytes, verbose=False):
        output = b""
        while len(output) < n_bytes:
            block = hashlib.sha256(self.state).digest()
            if verbose:
                print(f" [PRNG Generator Step] State: {self.state.hex()[:10]}... Block: {block.hex()[:10]}...")
            output += block
            self.state = hashlib.sha256(self.state).digest()
        return output[:n_bytes]


def xor_crypt(data, prng, verbose=False):
    keystream = prng.generate(len(data), verbose=verbose)
    encrypted = bytes(a ^ b for a, b in zip(data, keystream))
    return encrypted


# --- PART B: COMMUNICATION PROTOCOL ---

class Entity:
    def __init__(self, name):
        self.name = name
        self.private_key = secrets.randbelow(P - 1) + 1
        self.public_key = pow(G, self.private_key, P)
        self.session_prng = None

    def get_public_hex(self):
        return hex(self.public_key)

    def establish_session(self, partner_pub_hex, verbose=False, partner_name="partner", mallory_pub=None):
        partner_pub = int(partner_pub_hex, 16)
        shared_secret = pow(partner_pub, self.private_key, P)

        if verbose:
            if mallory_pub:
                print(f"[{self.name} Calculation] {truncate(mallory_pub)} ^ {truncate(self.private_key)} ... {truncate(self.private_key)} mod P")
            else:
                print(f"[{self.name} Calculation] {truncate(partner_pub)} ^ {truncate(self.private_key)} ... {truncate(self.private_key)} mod P")
            print(f"[{self.name} Calculated Shared Secret]: {truncate(shared_secret)}")

        self.session_prng = SecurePRNG(shared_secret)
        return shared_secret


# --- DO NOT MODIFY THIS CLASS --- #
class Network:
    def __init__(self):
        self.mallory = None

    def send(self, sender, recipient, payload):
        print(f"[NET] {sender} -> {recipient}: {str(payload)[:60]}...")
        if self.mallory:
            return self.mallory.intercept(sender, recipient, payload)
        return payload


# --- PART C: THE MALLORY MITM PROXY ---

class Mallory:
    def __init__(self):
        self.private_key = secrets.randbelow(P - 1) + 1
        self.public_key_int = pow(G, self.private_key, P)
        self.public_hex = hex(self.public_key_int)

        self.alice_prng = None
        self.bob_prng = None
        self.alice_secret = None
        self.bob_secret = None

    def intercept(self, sender, recipient, payload):
        if isinstance(payload, str) and payload.startswith("0x"):
            print(f"[ATTACK] Mallory intercepted Public Key destined for {recipient}!")

            remote_pub = int(payload, 16)
            my_shared_secret = pow(remote_pub, self.private_key, P)

            if sender == "Alice":
                self.alice_secret = my_shared_secret
                self.alice_prng = SecurePRNG(my_shared_secret)
                print(f"Mallory's Shared Secret with Alice: {truncate(my_shared_secret)}")
            elif sender == "Bob":
                self.bob_secret = my_shared_secret
                self.bob_prng = SecurePRNG(my_shared_secret)
                print(f"Mallory's Shared Secret with Bob: {truncate(my_shared_secret)}")

            print(f"[ATTACK] Mallory forwarding HER public key to {recipient}...")
            return self.public_hex

        if isinstance(payload, bytes):
            print(f"[ATTACK] Mallory intercepted encrypted message!")

            decrypted_bytes = xor_crypt(payload, self.alice_prng, verbose=True)
            try:
                plaintext = decrypted_bytes.decode()
                print(f"Mallory Decrypted Plaintext: {plaintext}")

                if "Kartheek" in plaintext:
                    modified = plaintext.replace("Kartheek", "Mallory")
                elif "9pm" in plaintext:
                    modified = plaintext.replace("9pm", "3am")
                else:
                    modified = plaintext

                print(f"[ATTACK] Mallory Modifying Payload to: '{modified}'")

                re_encrypted_payload = xor_crypt(modified.encode(), self.bob_prng, verbose=True)
                return re_encrypted_payload

            except Exception as e:
                print(f"[MALLORY] Error: {e}")
                return payload

        return payload


# --- DO NOT MODIFY THIS FUNCTION --- #
# --- MAIN EXECUTION SIMULATION ---
def main():

    # ==========================================
    # SCENARIO A: BENIGN (SECURE) COMMUNICATION
    # ==========================================
    print_header("SCENARIO A: BENIGN (SECURE) COMMUNICATION")

    alice = Entity("Alice")
    bob = Entity("Bob")
    net = Network()

    print("\nUsing Diffie-Hellman Parameters:")
    print(f"P (hex): {hex(P)}")
    print(f"G: {G}")
    print(f"Bit Length of P: {P.bit_length()} bits")

    print(f"\nAlice Private Key (a): {truncate(alice.private_key)}")
    print(f"Alice Public Key (g^a mod P): {truncate(alice.public_key)}")
    print(f"Bob Private Key (b): {truncate(bob.private_key)}")
    print(f"Bob Public Key (g^b mod P): {truncate(bob.public_key)}")

    print_step("Step 1: Public Key Exchange")
    alice_pub = alice.get_public_hex()
    bob_pub_hex_for_alice = net.send("Alice", "Bob", alice_pub)
    print(f"Bob received Key: {truncate(int(bob_pub_hex_for_alice, 16), 10, 10)}")

    bob_pub = bob.get_public_hex()
    alice_pub_hex_for_bob = net.send("Bob", "Alice", bob_pub)
    print(f"Alice received Key: {truncate(int(alice_pub_hex_for_bob, 16), 10, 10)}")

    print_step("Step 2: Calculating Shared Secrets")
    alice_secret = alice.establish_session(alice_pub_hex_for_bob, verbose=True, partner_name="Alice")
    bob_secret = bob.establish_session(bob_pub_hex_for_alice, verbose=True, partner_name="Bob")

    if alice_secret == bob_secret:
        print("[SUCCESS] Secrets Match! Secure Channel Established.")

    print_step("Step 3: Secure Message Transmission")
    message = b"Kartheek is learning cryptography"
    print(f"Alice sending: {message.decode()}")

    encrypted_msg = xor_crypt(message, alice.session_prng, verbose=True)
    print(f"Encrypted (Hex): {encrypted_msg.hex()}")

    delivered_data = net.send("Alice", "Bob", encrypted_msg)
    final_message = xor_crypt(delivered_data, bob.session_prng, verbose=True)

    print(f"Bob decrypted: {final_message.decode()}")
    if final_message == message:
        print("[SUCCESS] Communication Integrity Verified.")

    # ==========================================
    # SCENARIO B: MALICIOUS (MITM) ATTACK
    # ==========================================
    print_header("SCENARIO B: MALICIOUS (MITM) ATTACK")

    alice = Entity("Alice")
    bob = Entity("Bob")
    mallory = Mallory()
    net = Network()
    net.mallory = mallory

    print(f"\nAlice Private Key (a): {truncate(alice.private_key)}")
    print(f"Alice Public Key (g^a mod P): {truncate(alice.public_key)}")
    print(f"Bob Private (b): {truncate(bob.private_key)}")
    print(f"Bob Public Key (g^b mod P): {truncate(bob.public_key)}")
    print(f"Mallory Private Key (private_key): {truncate(mallory.private_key)}")
    print(f"Mallory Public Key (g^private_key mod P): {truncate(mallory.public_key_int)}")

    print_step("Step 1: Mallory infiltrates the Network")
    print("[ATTACK] Mallory is now active on the network line.")

    print_step("Step 2: Compromised Key Exchange")
    print("Alice sending key to Bob...")
    key_for_bob = net.send("Alice", "Bob", alice.get_public_hex())

    print("Bob sending key to Alice...")
    key_for_alice = net.send("Bob", "Alice", bob.get_public_hex())

    print_step("Step 3: Calculating Shared Secrets")
    alice_secret = alice.establish_session(key_for_alice, verbose=True, partner_name="Alice", mallory_pub=mallory.public_key_int)
    bob_secret = bob.establish_session(key_for_bob, verbose=True, partner_name="Bob", mallory_pub=mallory.public_key_int)

    print(f"Alice's Secret (with Mallory): {truncate(mallory.alice_secret)}")
    print(f"Bob's Secret (with Mallory): {truncate(mallory.bob_secret)}")

    if alice_secret != bob_secret:
        print("[ATTACK] NOTE: Alice and Bob have DIFFERENT secrets (MITM Successful).")

    print_step("Step 4: Active Message Interception")
    message = b"Kartheek is learning cryptography"
    print(f"Alice sending: {message.decode()}")

    encrypted_msg = xor_crypt(message, alice.session_prng, verbose=True)
    delivered_data = net.send("Alice", "Bob", encrypted_msg)

    print_step("Step 5: Victim Decryption")
    final_message = xor_crypt(delivered_data, bob.session_prng, verbose=True)
    print(f"Bob decrypted: {final_message.decode()}")

    if b"Mallory" in final_message:
        print("[ATTACK SUCCESS]: Bob received the modified message.")


if __name__ == "__main__":
    main()
