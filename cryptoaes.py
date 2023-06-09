import pyAesCrypt

buffersize = 64 * 1024

password = input("Give password")

Eord = str(input("Enter E to encrypt file or d to decrypt file"))

if(Eord == 'E'):
        try:
            pyAesCrypt.encryptFile("ct_marks.pdf", "ct_marks.pdf.aes", password, buffersize)
            print("File encrypted successfully")
        except EOFError as err:
            print(err)
               
elif(Eord == 'D'):
        try:
            pyAesCrypt.decryptFile("ct_marks.pdf.aes", "ct_marks_out.pdf", password, buffersize)
            print("File decryptFile successfully")
        except EOFError as err:
            print(err)
else:
         print("chode something")