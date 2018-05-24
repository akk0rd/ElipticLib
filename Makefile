all:
	gcc main.c bignum.c ecp.c ecp_curves.c -o ecp
clean:
	rm -rf ecp
