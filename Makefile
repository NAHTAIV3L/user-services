CFLAGS=-g -Wall

-include config.mak

all: pam_user_services.so user-servicesd user-services

%: %.c
	gcc $(CFLAGS) -o $@ $^

pam_user_services.so: pam_user_services.c
	gcc -fPIC -shared -o $@ $^ $(shell pkg-config --cflags --libs pam)

install: all
	install -m755 pam_user_services.so $(libdir)/security/
	install -m755 user-services $(bindir)/
	install -m755 user-servicesd $(bindir)/

clean:
	rm -f pam_user_services.so user-services user-servicesd

.PHONY: all install clean
