JFLAGS = -cp
JC = javac
JRUN = java

.SUFFIXES: .java .class

.java.class:
	$(JC) $(JFLAGS) NetSecProject.jar $*.java

CLASSES = \
	AES_128_Decryption.java \

default: classes

classes: $(CLASSES:.java=.class)

run: classes
	$(JRUN) $(JFLAGS) NetSecProject.jar AES_128_Decryption

clean:
	$(RM) *.class DecryptedText.txt 