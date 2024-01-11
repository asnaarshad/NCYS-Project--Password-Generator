import os
import string

from random import shuffle, randint

try:
    from secrets import choice
except ImportError:
    from random import choice


class PasswordGenerator:

    def __init__(self):
        self.minlen = 6
        self.maxlen = 16
        self.minuchars = 1
        self.minlchars = 1
        self.minnumbers = 1
        self.minschars = 1
        self.excludeuchars = ""
        self.excludelchars = ""
        self.excludenumbers = ""
        self.excludeschars = ""
        self.userId = ""
        self.lower_chars = string.ascii_lowercase
        self.upper_chars = string.ascii_uppercase
        self.numbers_list = string.digits
        self._schars = ["!", "#", "$", "%", "^", "&", "*", "(", ")", ",", ".", "-", "_", "+", "=", "<", ">", "?"]
        self._allchars = (
                list(self.lower_chars) + list(self.upper_chars) + list(self.numbers_list) + self._schars
        )

    # using sha256 algo to encrypt the generated password and then store it in a file

    def sha256(self, message):
        # Constants for SHA-256
        k_constants = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        ]

        # Initial hash values
        initial_hash_values = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ]

        original_length = len(message) * 8
        message += b'\x80'
        while (len(message) + 8) % 64 != 0:
            message += b'\x00'
        message += original_length.to_bytes(8, 'big')

        # Helper functions
        def right_rotate(val, n):
            return (val >> n) | (val << (32 - n)) & 0xFFFFFFFF

        for chunk_start in range(0, len(message), 64):
            current_chunk = message[chunk_start:chunk_start + 64]
            words = [int.from_bytes(current_chunk[i:i + 4], 'big') for i in range(0, 64, 4)]

            # Message schedule
            for i in range(16, 64):
                s0_temp = right_rotate(words[i - 15], 7) ^ right_rotate(words[i - 15], 18) ^ (words[i - 15] >> 3)
                s1_temp = right_rotate(words[i - 2], 17) ^ right_rotate(words[i - 2], 19) ^ (words[i - 2] >> 10)
                words.append((words[i - 16] + s0_temp + words[i - 7] + s1_temp) & 0xFFFFFFFF)

            # Initialize working variables
            h0_temp, h1_temp, h2_temp, h3_temp, h4_temp, h5_temp, h6_temp, h7_temp = initial_hash_values

            # Compression function
            for i in range(64):
                s1_temp = right_rotate(h5_temp, 6) ^ right_rotate(h5_temp, 11) ^ right_rotate(h5_temp, 25)
                ch_temp = (h5_temp & h6_temp) ^ (~h5_temp & h7_temp)
                temp1_temp = (h7_temp + s1_temp + ch_temp + k_constants[i] + words[i]) & 0xFFFFFFFF
                s0_temp = right_rotate(h0_temp, 2) ^ right_rotate(h0_temp, 13) ^ right_rotate(h0_temp, 22)
                maj_temp = (h0_temp & h1_temp) ^ (h0_temp & h2_temp) ^ (h1_temp & h2_temp)
                temp2_temp = (s0_temp + maj_temp) & 0xFFFFFFFF

                h7_temp = h6_temp
                h6_temp = h5_temp
                h5_temp = h4_temp
                h4_temp = (h3_temp + temp1_temp) & 0xFFFFFFFF
                h3_temp = h2_temp
                h2_temp = h1_temp
                h1_temp = h0_temp
                h0_temp = (temp1_temp + temp2_temp) & 0xFFFFFFFF

            # Update hash values
            initial_hash_values = [((x + y) & 0xFFFFFFFF) for x, y in
                                   zip(initial_hash_values,
                                       [h0_temp, h1_temp, h2_temp, h3_temp, h4_temp, h5_temp, h6_temp, h7_temp])]

        # Produce the final hash value
        hash_hex = ''.join(format(val, '08x') for val in initial_hash_values)
        return hash_hex


    def generate(self):
        # Generates a password using default or custom properties
        if (
                self.minlen < 0
                or self.maxlen < 0
                or self.minuchars < 0
                or self.minlchars < 0
                or self.minnumbers < 0
                or self.minschars < 0
        ):
            raise ValueError("Character length should not be negative")

        if self.minlen > self.maxlen:
            raise ValueError(
                "Minimum length cannot be greater than maximum length. The default maximum length is 16."
            )

        collectiveMinLength = (
                self.minuchars + self.minlchars + self.minnumbers + self.minschars
        )

        if collectiveMinLength > self.minlen:
            self.minlen = collectiveMinLength

        final_pass = [
            choice(list(set(self.lower_chars) - set(self.excludelchars)))
            for i in range(self.minlchars)
        ]
        final_pass += [
            choice(list(set(self.upper_chars) - set(self.excludeuchars)))
            for i in range(self.minuchars)
        ]
        final_pass += [
            choice(list(set(self.numbers_list) - set(self.excludenumbers)))
            for i in range(self.minnumbers)
        ]
        final_pass += [
            choice(list(set(self._schars) - set(self.excludeschars)))
            for i in range(self.minschars)
        ]

        currentpasslen = len(final_pass)
        all_chars = list(
            set(self._allchars)
            - set(
                list(self.excludelchars)
                + list(self.excludeuchars)
                + list(self.excludenumbers)
                + list(self.excludeschars)
            )
        )

        if len(final_pass) < self.maxlen:
            randlen = randint(self.minlen, self.maxlen)
            final_pass += [choice(all_chars) for i in range(randlen - currentpasslen)]

        shuffle(final_pass)
        return "".join(final_pass)

    def generateEmail(self, userId):
        uid = userId[2] + userId[:2] + userId[3:]
        email = uid + "@nu.edu.pk"
        return "".join(email)

    def signup(self):

        print("====================Signup===================")
        pwo = PasswordGenerator()

        # Validate and set the user ID
        while True:
            pwo.userId = input("Enter your User Id: ")

            # Check if the user ID matches the specified criteria
            if len(pwo.userId) == 7 and pwo.userId[:2].isdigit() and pwo.userId[2].upper() == 'K' and pwo.userId[
                                                                                                      3:].isdigit():

                # Check file exists or not
                if not os.path.exists('user_info.txt'):
                    # Create file if it doesn't exists
                    with open('user_info.txt', 'w') as file:
                        pass  # Empty file for now

                # read file to check if user already exists
                with open('user_info.txt', 'r') as file:
                    # Check if the file is empty
                    lines = file.readlines()
                    if lines:
                        for line in lines:
                            stored_user_id, email, hashed_password = line.strip().split(',', 2)
                            if pwo.userId == stored_user_id:
                                print("User already exists! Please use another id.")
                                break
                        else:
                            break
            else:
                print("Invalid User ID. Please follow the specified format (e.g., 21K2000).")

        print("Input the following details to generate the password:")
        # Validate and set the uppercase characters
        while True:
            try:
                ucase = int(input("Enter uppercase characters you want in your password: "))
                pwo.minuchars = ucase
                break
            except ValueError:
                print("Invalid input!")

        # Validate and set the lowercase characters
        while True:
            try:
                lcase = int(input("Enter lowercase characters you want in your password: "))
                pwo.minlchars = lcase
                break
            except ValueError:
                print("Invalid input!")

        # Validate and set the numbers
        while True:
            try:
                num = int(input("Enter numbers you want in your password: "))
                pwo.minnumbers = num
                break
            except ValueError:
                print("Invalid input!")

        # Validate and set the special characters
        while True:
            try:
                schars = int(input("Enter special characters you want in your password: "))
                pwo.minschars = schars
                break
            except ValueError:
                print("Invalid input!")

        paslen = ucase + lcase + num + schars
        pwo.minlen = paslen
        pwo.maxlen = paslen

        # Generate and print the email and password
        email = pwo.generateEmail(pwo.userId)
        print("\nEmail: " + pwo.generateEmail(pwo.userId))
        generatedPas = pwo.generate()
        print("Generated Password: " + generatedPas)

        # hash the generated password to store in file
        hashed_password = pwo.sha256(generatedPas.encode())
        # save user info in file
        with open('user_info.txt', 'a') as file:
            file.write(f'{pwo.userId},{email},{hashed_password}\n')

        return

    def login(self):
        print("====================Login======================")
        # take email input
        useremail = input("Enter email: ")

        # Read data from file
        user_data = {}
        with open('user_info.txt', 'r') as f:
            user_info = f.readlines()
            for line in user_info:
                # Split the line into id, email, password by the second occurrence of comma as the password can also contain commas
                userid, email, hashed_password = line.strip().split(',', 2)
                user_data[email] = hashed_password
        # Authentication
        # Check if the email is in user data
        if useremail in user_data:
            password = input("Enter password: ")
            # Compare the entered password with the stored hash
            stored_hashed_password = user_data[useremail]
            entered_hashed_password = pwo.sha256(password.encode())

            if stored_hashed_password == entered_hashed_password and useremail == email:
                print("Login successful!")
            else:
                print("Invalid email or password!")
        else:
            print("User not found!")
        return


if __name__ == '__main__':
    # Create an instance of the PasswordGenerator class
    pwo = PasswordGenerator()
    print("============= Password Generator ==============")
    print("========= Created by Aaminah & Asna ===========")

    option = int(input("Do you want to: \n1:Login \n2:Signup\n"))
    if option == 1:
        pwo.login()
    elif option == 2:
        pwo.signup()
    else:
        print("=====================Exit======================")
