all: sha1_password_crack
	
sha1_password_crack: sha1_password_crack.c
	gcc -o sha1_password_crack sha1_password_crack.c -L/usr/local/opt/openssl/lib/ -I/usr/local/opt/openssl/include/ -lcrypto


clean:
	rm sha1_password_crack
