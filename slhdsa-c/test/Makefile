CSRC	 =	$(wildcard ../slh/*.c) $(wildcard ../hash/*.c)
OBJS	 =	$(CSRC:.c=.o)

XCOUNT	?=	xcount
XCOUNTC	 =	xcount.c dbg.c

CC 		 =	gcc
CFLAGS	:=	-Wall -Wextra -march=native -O3 
#CFLAGS	+=	-fsanitize=address,undefined
CFLAGS	+=	-I../hash -I../slh -DSLH_EXPERIMENTAL
LDLIBS	+=

$(XCOUNT): $(OBJS) xcount.c dbg.c
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(OBJS) $(XCOUNTC) $(LDLIBS)

%.o: %.[cS]
	$(CC) $(CFLAGS) -c $^ -o $@

new_param.csv: $(XCOUNT) test_param.py new_param.txt
	echo "alg_id, pk, sk, sig, keygen, sign, vfy_ok, vfy_fail"> $@
	./$(XCOUNT) | tee /dev/tty | sort >> $@
	python3 test_param.py | parallel | tee /dev/tty | sort >> $@

clean:
	$(RM) -rf $(XCOUNT) $(OBJS) *.log
	$(RM) -f *.pyc *.cprof */*.pyc *.rsp *.log
	$(RM) -rf __pycache__ */__pycache__
