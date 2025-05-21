# /opt/homebrew/bin/python3 -m venv venv
# source venv/bin/activate
# pip install pycryptodome

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
import base64
import xml.etree.ElementTree as ET
import re
import sys 
import os


KEY_SEED_STRING = "354411525419247default"
IV_STRING = "gcQu4mcDjQkPjcX1YY2X6xNaWyiWF0dUNbA"

# AES algorithm and mode details (as inferred from Smali)
# ALGORITHM_SMALI = "AES/CBC/PKCS5Padding" 
# Python's pycryptodome uses AES.MODE_CBC and then pkcs7 unpadding.

def derive_aes_key(seed_string):
    """Derives the AES-256 key by SHA-256 hashing the seed string."""
    sha256 = hashlib.sha256()
    sha256.update(seed_string.encode('utf-8'))
    return sha256.digest() # Returns 32 bytes (256 bits) for AES-256

def get_iv():
    """Gets the first 16 bytes of the IV string for AES."""
    # AES block size is 16 bytes
    return IV_STRING.encode('utf-8')[:16]

def decrypt_value(base64_encrypted_string, key_to_use, iv_to_use):
    """Decrypts a Base64 encoded, AES/CBC/PKCS5Padding (effectively PKCS7 for AES) encrypted string."""
    try:
        # Step 1: Decode the string from Base64 to bytes
        encrypted_bytes = base64.b64decode(base64_encrypted_string)
        
        # Step 2: Create the AES cipher object in CBC mode
        cipher = AES.new(key_to_use, AES.MODE_CBC, iv_to_use)
        
        # Step 3: Decrypt the bytes
        decrypted_padded_bytes = cipher.decrypt(encrypted_bytes)
        
        # Step 4: Remove PKCS#7 padding
        # PKCS5Padding is a subset of PKCS7Padding for 8-byte blocks.
        # For AES (16-byte blocks), PKCS7 unpadding is appropriate.
        decrypted_bytes = unpad(decrypted_padded_bytes, AES.block_size, style='pkcs7')
        
        # Step 5: Convert the decrypted bytes to a UTF-8 string
        decrypted_string = decrypted_bytes.decode('utf-8')
        
        return decrypted_string
        
    except ValueError as e: # Catches errors like incorrect padding
        # These specific error messages can help diagnose if the key/IV is wrong
        # or if the data isn't what we expect (e.g., not actually encrypted this way).
        if "Padding is incorrect." in str(e) or "PKCS#7 padding is incorrect" in str(e):
            # This is a common error if the key or IV is wrong, or if the data was not padded
            # with PKCS7 or if it's corrupted.
            # print(f"Debug: Padding error for '{base64_encrypted_string}'. Key/IV mismatch or data corruption suspected.")
            pass
        elif "Incorrect IV length" in str(e):
            # This shouldn't happen if get_iv() is correct.
            # print(f"Debug: Incorrect IV length. IV used: {len(iv_to_use)} bytes.")
            pass
        # else:
            # print(f"Debug: Decryption ValueError for '{base64_encrypted_string}': {e}")
        return None # Return None if decryption fails for any ValueError reason
    except Exception:
        # Catch other generic errors (e.g., Base64 decoding issues if input isn't valid Base64)
        # print(f"Debug: Generic decryption error for '{base64_encrypted_string}': {e}")
        return None # Return None for other errors

def is_potentially_base64_encrypted(value):
    """
    Heuristically checks if a string might be Base64 encoded and thus a candidate for decryption.
    Looks for typical Base64 characters and padding.
    """
    if not isinstance(value, str) or len(value) < 8: # Very short strings are unlikely AES+Base64
        return False
    # Pattern for Base64 strings: alphanumeric characters, +, /, and optionally = padding at the end.
    # A stricter check could also ensure only valid Base64 characters are present.
    # Length must be a multiple of 4 for padded Base64.
    return re.match(r'^[A-Za-z0-9+/]*={0,2}$', value) is not None and len(value) % 4 == 0

# --- Main script execution ---
if __name__ == "__main__":
    # Check if an input file path is provided as a command-line argument
    if len(sys.argv) < 2:
        print("Error: No input file specified.")
        print("Usage: python decrypt_prefs.py <input_xml_file_path>")
        print("Example: python decrypt_prefs.py /path/to/your/prefs.xml")
        sys.exit(1) # Exit if no input file is provided

    input_xml_file = sys.argv[1] # Get the input file path from the first command-line argument
    
    # Check if the input file exists
    if not os.path.isfile(input_xml_file):
        print(f"Error: Input file '{input_xml_file}' not found.")
        sys.exit(1)

    # Construct the output file name by appending "_decrypted" before the extension
    file_name, file_extension = os.path.splitext(input_xml_file)
    output_xml_file = f"{file_name}_decrypted{file_extension}"

    # Try to parse the input XML file
    try:
        tree = ET.parse(input_xml_file)
        root = tree.getroot()
    except ET.ParseError:
        print(f"Error: Could not parse XML file '{input_xml_file}'. Please ensure it is valid XML.")
        sys.exit(1)

    # Derive the AES key and IV once for efficiency
    derived_key = derive_aes_key(KEY_SEED_STRING)
    derived_iv = get_iv()

    print(f"Processing file: {input_xml_file}")
    print(f"Derived AES Key (hex): {derived_key.hex()}")
    print(f"Derived IV (hex): {derived_iv.hex()}")
    print("-" * 30)

    decryption_count = 0
    failed_decryption_count = 0
    processed_strings_count = 0

    # Process the XML tree if the root tag is '<map>' (typical for SharedPreferences XML)
    if root.tag == 'map':
        for element in root: # Iterate through child elements of <map>
            if element.tag == 'string': # Process only <string> tags
                processed_strings_count +=1
                key_name = element.get('name') # Get the 'name' attribute of the <string> tag
                original_value = element.text   # Get the text content of the <string> tag
                # print(key_name)
                # Check if the value is not None/empty and looks like a candidate for decryption
                if original_value and is_potentially_base64_encrypted(original_value):
                    # Optional: More verbose logging during processing
                    # print(f"Attempting to decrypt key: '{key_name}', encrypted value: '{original_value}'")
                    decrypted_text = decrypt_value(original_value, derived_key, derived_iv)
                    
                    if decrypted_text is not None:
                        # print(f"  -> Decrypted to: '{decrypted_text}'") # Verbose log
                        element.text = decrypted_text # Replace the element's text with the decrypted one
                        decryption_count += 1
                    else:
                        # print(f"  -> Decryption failed for key: '{key_name}'. Keeping original value.") # Verbose log
                        failed_decryption_count += 1
            # Logic for other tag types (e.g., <boolean>, <int>) could be added here if needed.
            # However, encrypted values are most commonly stored as strings.

    # Write the modified (or original, if no changes) XML tree to the output file
    try:
        # ET.indent(tree, space="\t", level=0) # For pretty-printing if Python version supports it (3.9+)
        tree.write(output_xml_file, encoding='utf-8', xml_declaration=True)
        print("-" * 30)
        print(f"Decrypted XML file saved to: {output_xml_file}")
        print(f"Total <string> elements processed: {processed_strings_count}")
        print(f"Successfully decrypted values: {decryption_count}")
        if failed_decryption_count > 0:
            print(f"Failed decryption attempts (original value kept): {failed_decryption_count}")
    except IOError:
        print(f"Error: Could not write to output file '{output_xml_file}'. Check permissions or path.")
        sys.exit(1)
    import sys # Needed for sys.exit()
    import os  # Needed for os.path

    if len(sys.argv) < 2:
        print("Usage: python decrypt_prefs.py <input_xml_file_path>")
        print("Example: python decrypt_prefs.py /path/to/your/prefs.xml")
        sys.exit(1)

    input_xml_file = sys.argv[1]
    
    if not os.path.isfile(input_xml_file):
        print(f"Error: Input file '{input_xml_file}' not found.")
        sys.exit(1)

    # Construct the output file name
    file_name, file_extension = os.path.splitext(input_xml_file)
    output_xml_file = f"{file_name}_decrypted{file_extension}"

    try:
        tree = ET.parse(input_xml_file)
        root = tree.getroot()
    except ET.ParseError:
        print(f"Error: Could not parse XML file '{input_xml_file}'. Please ensure it is valid XML.")
        sys.exit(1)

    # Derive the AES key and IV once
    derived_key = derive_aes_key(KEY_SEED_STRING)
    derived_iv = get_iv()

    print(f"Processing file: {input_xml_file}")
    print(f"Derived AES Key (hex): {derived_key.hex()}")
    print(f"Derived IV (hex): {derived_iv.hex()}")
    print("-" * 30)

    decryption_count = 0
    failed_decryption_count = 0
    processed_strings = 0

    if root.tag == 'map':
        for element in root:
            if element.tag == 'string': # Process only <string> tags
                processed_strings +=1
                key_name = element.get('name')
                original_value = element.text

                if original_value and is_potentially_base64_encrypted(original_value):
                    # print(f"Attempting to decrypt key: '{key_name}', encrypted value: '{original_value}'") # Optional: for verbose logging
                    decrypted_text = decrypt_value(original_value, derived_key, derived_iv)
                    
                    if decrypted_text is not None:
                        # print(f"  -> Decrypted to: '{decrypted_text}'") # Optional: for verbose logging
                        element.text = decrypted_text # Replace the element's text with the decrypted one
                        decryption_count += 1
                    else:
                        # print(f"  -> Decryption failed for key: '{key_name}'. Keeping original value.") # Optional: for verbose logging
                        failed_decryption_count += 1
            # You can add logic for other tag types here if needed (e.g., <boolean>, <int>)
            # but encryption is usually applied to string values which are then converted.

    # Write the modified XML tree to the output file
    try:
        tree.write(output_xml_file, encoding='utf-8', xml_declaration=True)
        print("-" * 30)
        print(f"Decrypted XML file saved to: {output_xml_file}")
        print(f"Total <string> elements processed: {processed_strings}")
        print(f"Successfully decrypted values: {decryption_count}")
        if failed_decryption_count > 0:
            print(f"Failed decryption attempts (original value kept): {failed_decryption_count}")
    except IOError:
        print(f"Error: Could not write to output file '{output_xml_file}'.")
        sys.exit(1)