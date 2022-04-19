# secure-message
Cryptographically Secure Messaging Interface

To run this code:

1. Clone this repo 
2. Create an Amazon S3 bucket and put bucket information in `main.py` (Both the writeAWS and readAWS functions)
3. Run the make command and see all the output in `output.txt`
4. `output.txt` has all cryptographic information for three test messages
5. You can compare to the `Output Example.txt` file, which is what the ouput should be for the 3 test messages once the AWS bucket is set up 


###### SHA3_512 code is from the Keccak team
###### Credit @gaatorre for the AWS S3 code
