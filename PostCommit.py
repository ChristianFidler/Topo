from eth_account import Account
from utils import (
    save_proof_and_signatures_json, load_private_key, 
    compute_sha256, sign_proof_object, verify_signature, compute_file_hash, 
    process_file, get_commit_hash
)

# Main logic to generate proof after data analysis
if __name__ == "__main__":
    # Load private key and public key
    private_key = load_private_key("private_key.txt")
    public_key = private_key.public_key

    # Generate Ethereum account from private key
    account = Account.from_key(private_key)

    # Get current commit hash and compute file hash
    commit_hash = get_commit_hash()
    file_hash = compute_file_hash("input.txt")

    # Display commit and file hash for verification
    print("\nPlease verify that this matches your precommitted analysis")
    print(f"Current commit hash: {commit_hash}")
    print(f"Input file hash: {file_hash}")

    # Create pre-object for analysis
    pre_object = {'code_hash': commit_hash, 'file_hash': file_hash}
    pre_hash, signatureA = sign_proof_object(private_key, pre_object)

    # Display the pre-analysis hash
    print(f"Analysis hash: {pre_hash}")

    # Run the analysis and generate proof object
    seed = 42
    data_hash = '00000001'

    # Process the file and extract Merkle roots
    _, roots = process_file("chain.txt", skip=10, rounding=5)

    # Create the final proof object
    proof_object = {'roots': roots, 'data_hash': data_hash, 'seed': seed, 'pre_hash': pre_hash}
    H_output, signatureB = sign_proof_object(private_key, proof_object)

    # Verify the final proof object signature
    is_valid = public_key.verify_msg_hash(compute_sha256(str(proof_object).encode()), signatureB)

    # Display the final output and signatures
    print("\nPublish all of the following:")
    print(f"Committed main hash: {H_output}")
    print(f"Proof object: {proof_object}")
    print(f"Signature valid: {is_valid}")
    print(f"Signature: {signatureB}")

    # Save the proof object, signatures, and public key to a JSON file
    save_proof_and_signatures_json('proof_object.json', proof_object, signatureA, signatureB, public_key)
    print('proof-object saved in json')


