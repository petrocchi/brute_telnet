# brute_telnet.c - Telnet bruteforce, for penetration test

This is a tool for penetration test the telnet remote login. This tool use brute force tecnique, for crack the remote authentication service telnet, with parallel connection.

THIS TOOL IS FOR LEGAL PURPOSES ONLY!




### COMPILE:

For compile you need to linker de pthread library.
```sh
bar@kali$ gcc -o brute_telnet brute_telnet.c -pthread
```



### USE:

```sh
bar@kali:~$ ./brute_telnet
[+] Login Bruteforce telnet server, for penetration test...

Usage: ./brute_telnet <host> <port> <userfile> <passfile> <n thread> [options]

<userfile>	File user list
<passdile>	File password list
<n threads>	Numober of parallel threads

Options:
	-v	Verbose mode

Examples:
	./brute_telnet 192.168.1.1 23 user.txt wordlist.txt 30
	./brute_telnet 192.168.1.1 23 user.txt wordlist.txt 30 -v

bar@kali:~$
```
