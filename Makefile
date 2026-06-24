CFLAGS=-g -Wall

all: pam_user_services.so user-servicesd user-services

%: %.c
	gcc $(CFLAGS) -o $@ $^

pam_user_services.so: pam_user_services.c
	gcc -fPIC -shared -o $@ $^ $(shell pkg-config --cflags --libs pam)
