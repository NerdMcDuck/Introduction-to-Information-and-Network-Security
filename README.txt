TO RUN:

If running on Linux: make run
This will run the makefile which compile the code and runs it

If running on Windows 
To compile:
javac -classpath NetSecProject.jar AES_128_Decryption.java

To run:
java -classpath NetSecProject.jar AES_128_Decryption

The ciphertext and keys are hard coded into the program. 
Once ran it will output the plaintext as well as the key in a file called "Decryptedtext.txt"
First two should take a couple seconds, last two will take significantly longer. 

Makefile

Aside from running the code the make file has a "clean" command.
"make clean" will delete the .class and .txt files. 