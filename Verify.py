from utils import (
    compute_sha256, get_commit_hash, compute_file_hash, 
    verify_file_hash, process_file_and_verify_roots, load_proof_and_signatures_json, 
    verify_committed_hash, verify_signature_hex
)

if __name__ == "__main__":
    # Load the proof object, signatures, and public key
    proof, signature_hex, signatureB, public_key_hex = load_proof_and_signatures_json("proof_object.json")

    # Gather pre-committed data from the proof
    pre_hash = proof['pre_hash']
    file_path = "input.txt"

    # Flag to control whether the code should be run after verifications
    run_code = True

    # Recompute the code and file hash
    file_hash = compute_file_hash(file_path)
    code_hash = get_commit_hash()
    pre_object = {'code_hash': code_hash, 'file_hash': file_hash}

    
    # Step 1: Verify the committed pre-object hash
    if verify_committed_hash(pre_object, pre_hash):
        print('Pre hash verified: You are running the correct analysis pipeline.')
    else:
        print('Committed hash not verified: The code or input file version might be incorrect.')
        run_code = False

    # Step 2: Verify the signature on the pre-object
    pre_object_hash = compute_sha256(str(pre_object).encode())
    if verify_signature_hex(public_key_hex, pre_object_hash, signature_hex):
        print('Signature valid: Prover authenticity established.')
    else:
        print('Signature invalid: Could not authenticate the analysis hash.')
        #run_code = False

    # Step 3: Display data hash and seed for manual verification
    print("\nPlease verify the following:")
    print(f"Data fingerprint: {proof['data_hash']} (verify against the used data).")
    print(f"Seed used: {proof['seed']}")
    print(f"Public Key of Prover: {public_key_hex}")

    # Step 4: Verify the signature on the full proof object
    proof_hash = compute_sha256(str(proof).encode())
    if verify_signature_hex(public_key_hex, proof_hash, signatureB):
        print('Proof signature valid: Identity and proof object verified.')
    else:
        print('Signature invalid: Proof object may have been tampered with or prover authenticity cannot be confirmed.')
        run_code = False

    # Step 5: If all verifications passed, proceed with processing the file
    if run_code:
        #run the code
        process_file_and_verify_roots("testchain.txt", proof['roots'], skip=10, rounding=5)
    else:
        print('Verification failed: Process aborted.')
