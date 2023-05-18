# tinytsh.c - A tiny shell program with job control written in C.
Written as part of CMU's Computer Systems Course. Received a 100% grade.
## Info on shells
A shell a program that takes commands from the keyboard and gives them to the operating system to perform. It continuously read and evaluates command line arguments in a loop.
## How my implementation works
My implementation uses the main function to parse the command line and initialize all environment variables, structures, and values. It then repeatedly uses the ```<eval>``` function to evaluate the command line. I provide custom functions to handle signals to parent and child processes. Additionally, I handle background and foreground processes in their respective functions.
### High-level overview:
1. Command line parsed.
2. Built-in commands evaluated.
3. Child process forked, non-built-in command run within child.
4. Global resources cleaned up upon program exit.
## Demos
The version publicly available in this repository does not work on its own. For demos, please contact me at iltikinw@gmail.com, and I'd love to connect!