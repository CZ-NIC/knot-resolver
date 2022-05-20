main: main.c
	gcc main.c -Wall -Wextra -pedantic -o main

.PHONY: run
run: main
	poetry run ./main -c etc/knot-resolver/config.dev.yml