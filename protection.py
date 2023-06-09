from PyPDF2 import  PdfWriter, PdfReader

pdfwriter = PdfWriter()

pdf = PdfReader("ct_marks.pdf")

for page_num in range(len(pdf.pages)):
    pdfwriter.add_page(pdf.pages[page_num])
    
password = "sourav"
pdfwriter.encrypt(password)

with open("new_pdf.pdf", "wb") as f:
    pdfwriter.write(f)
    f.close()