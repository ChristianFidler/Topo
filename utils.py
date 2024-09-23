import subprocess

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from eth_keys import keys
from eth_account.messages import encode_defunct
from eth_account import Account
from eth_utils import keccak
from pymerkle import InmemoryTree as MerkleTree
import os
import json

# Function to load a private key from file
def load_private_key(file_path):
    with open(file_path, "rb") as f:
        private_key_bytes = f.read()
    return keys.PrivateKey(private_key_bytes)

# Function to compute SHA-256 hash of a message
def compute_sha256(message):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message)   

    #return keccak(message)  # Ethereum uses Keccak-256 for hashing the message


    return digest.finalize()

# Function to hash and sign a message
def sign_message(private_key, message):
    message_hash = compute_sha256(message)
    signature = private_key.sign_msg_hash(message_hash)
    return signature

# Function to verify a signature
def verify_signature(public_key, message, signature):
    message_hash = compute_sha256(message)
    return public_key.verify_msg_hash(message_hash, signature)

# Function to compute file hash (SHA-256)
def compute_file_hash(file_path):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            digest.update(chunk)
    return digest.finalize().hex()

# Function to process data from a file using Merkle Tree and rounding
def process_file(file_path, skip=10, rounding=5):
    tree = MerkleTree(hash_type='sha256')
    roots = []
    
    with open(file_path, 'r') as f:
        for i, line in enumerate(f, start=1):
            if i % skip == 0:
                rounded_numbers = [round(float(num), rounding) for num in line.strip().split(',')]
                tree.append_entry(str(rounded_numbers).encode())
                if is_power_of_two(tree.get_size()):
                    roots.append(tree.get_state().hex())
    
    if not is_power_of_two(tree.get_size()):
        roots.append(tree.get_state().hex())
    
    return tree, roots

# Function to hash and sign an object (proof)
def sign_proof_object(private_key, proof_object):
    proof_str = str(proof_object).encode()
    proof_hash = compute_sha256(proof_str)
    signature = private_key.sign_msg_hash(proof_hash)
    return proof_hash.hex(), signature

def get_commit_hash():
    try:
        # Run git command to get the commit hash
        commit_hash = subprocess.check_output(['git', 'rev-parse', 'HEAD']).strip().decode('utf-8')
        return commit_hash
    except subprocess.CalledProcessError as e:
        return f"Error: {e}"


def save_proof_and_signatures_json(filename, proof_object, signatureA, signatureB, public_key):
    data_to_save = {
        'proof_object': proof_object,
        'signatureA': str(signatureA), 
        'signatureB': str(signatureB),  
        'public_key': str(public_key) 
    }
    
    with open(filename, 'w') as f:
        json.dump(data_to_save, f, indent=4)



# Utility function to check if a number is a power of two
def is_power_of_two(n):
    return n > 0 and (n & (n - 1)) == 0




# Function to verify file hash against the pre-committed value
def verify_file_hash(file_path, expected_hash):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            digest.update(chunk)
    file_hash = digest.finalize().hex()
    return file_hash == expected_hash

# Function to verify hash of an object (pre_object or proof)
def verify_committed_hash(object_to_hash, committed_hash):
    computed_hash = compute_sha256(str(object_to_hash).encode()).hex()
    return computed_hash == committed_hash

# Function to verify signature using public key
def verify_signature_hex(public_key_hex, message_hash, signature_hex):
    public_key_bytes = bytes.fromhex(public_key_hex[2:])
    public_key = keys.PublicKey(public_key_bytes)
    signature_bytes = bytes.fromhex(signature_hex[2:])
    signature = keys.Signature(signature_bytes)
    return public_key.verify_msg_hash(message_hash, signature)

# Function to process file and verify Merkle Tree roots
def process_file_and_verify_roots(file_path, proof_roots, skip=10, rounding=5, full_verification=False):
    tree = MerkleTree(hash_type='sha256')
    level = 1
    
    with open(file_path, 'r') as f:
        for i, line in enumerate(f, start=1):
            if i % skip == 0:
                rounded_numbers = [round(float(num), rounding) for num in line.strip().split(',')]
                tree.append_entry(str(rounded_numbers).encode())
                
                if is_power_of_two(tree.get_size()):
                    root_hash = tree.get_state().hex()
                    if root_hash in proof_roots:
                        print(f'Verification passed at level {level}')
                        level += 1
                    else:
                        print('Verification failed')
    
    if full_verification and not is_power_of_two(tree.get_size()):
        root_hash = tree.get_state().hex()
        if root_hash in proof_roots:
            print('Full verification passed')
        else:
            print('Verification failed')


def load_proof_and_signatures_json(filename):
    with open(filename, 'r') as f:
        data = json.load(f)

    # Load the proof object
    proof_object = data['proof_object']

    signatureA = data['signatureA']
    signatureB = data['signatureB']

    public_key = data['public_key']

    return proof_object, signatureA, signatureB, public_key

def generate_keys():
    private_key_bytes = os.urandom(32)
    private_key = keys.PrivateKey(private_key_bytes)
    
    if os.path.exists("private_key.txt"):
        user_input = input("Key file already exists. Do you want to overwrite it? (yes/no): ").strip().lower()
        if user_input != 'yes':
            print("Aborting key generation to avoid overwriting.")
            return
    
    with open("private_key.txt", "wb") as f:
        f.write(private_key_bytes)
    print("Keys generated and saved to private_key.txt.")
