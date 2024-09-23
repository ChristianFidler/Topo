from eth_account import Account
from utils import (
    load_private_key, compute_sha256, sign_message, 
    verify_signature, compute_file_hash, process_file, 
    sign_proof_object, get_commit_hash
)
 

def main():
    """
    Main function to orchestrate the hash generation and display the analysis information.
    """
    # Load private key and derive public key
    private_key = load_private_key("private_key.txt")
    public_key = private_key.public_key
    # Generate account from private key (Ethereum address)
    account = Account.from_key(private_key)


    # get git commit hash
    code_hash = get_commit_hash()
    # Compute file hash for input file
    file_hash = compute_file_hash("input.txt")
    
    # Commit hashes into a pre-object
    pre_object = {'code_hash': code_hash, 'file_hash': file_hash}
    pre_hash, signature = sign_proof_object(private_key, pre_object)
    
    # Verify pre-object signature
    is_valid = public_key.verify_msg_hash(compute_sha256(str(pre_object).encode()), signature)

    print("\nInformation to publish with timestamp:")
    print(f"Analysis hash: {pre_hash}")
    print(f"Signature: {signature}")
    print(f"Testing Signature: {is_valid}")

    print("\nIf not known publicly yet: publish")
    print(f"Public Key: {public_key}")
    print(f"Ethereum Address: {account.address}")

    print("Please keep corresponding private key safe")

    print("\npublish now, or later if code is still secret")
    print(f"The input file, and the git branch: {code_hash}")


if __name__ == "__main__":
    main()



