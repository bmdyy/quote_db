# QuoteDB (Vulnerable TCP Server)

QuoteDB is a command line server which runs on Win32. It is vulnerable
by design with the purpose of being an application to practice reverse engineering / exploit development on.

It is intended to be compiled with ASLR and DEP protections enabled. A compiled version with these enabled is in the releases section.

I created this program while taking the EXP-301 course to practice for the exam.

## Goal

The intended way to approach this challenge is to download the .exe, and create an exploit which bypasses ASLR and DEP to give a reverse shell. 

You should not look at the source code until solved, if you want to practice reverse engineering.

## How to compile

To compile without any protections:
- `gcc main.c -o main.exe -l ws2_32`

To compile with DEP:
- `gcc main.c -o main.exe -l ws2_32 -Wl,--nxcompat`

To compile with ASLR:
- `gcc main.c -o main.exe -l ws2_32 -Wl,--dynamicbase`

To compile with DEP + ASLR:
- `gcc main.c -o main.exe -l ws2_32 -Wl,--nxcompat,--dynamicbase`

## How to run

To run on the default port (3700):
- `.\main.exe`

To run on a custom port:
- `.\main.exe -p PORT`

## Solution

A solution PoC script is included (`poc.py`). I recommend that you don't look at it until after solving the challenge, as it will spoil the fun.