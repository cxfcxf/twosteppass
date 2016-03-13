# twosteppass pam module for ssh

## how to compile

```
# gcc -fPIC -fno-stack-protector -lcurl -c twosteppass.c
# ld -lcurl -x --shared -o /lib64/security/twosteppass.so twosteppass.o
```

## before you use
you need to enable following line in your openssh config
```
ChallengeResponseAuthentication yes
```

and include the module in your /etc/pam.d/sshd
```
auth	required	twosteppass.so
```

setup up webserver which serves random page
and in crontab you can do something like
```
*/5 * * * * /bin/echo $RANDOM > /var/www/htdoc/random
```

change the line in twosteppass.c to point to the random number page you have

### this is good with people have lagcy system, dont want to change any stuff and redo user account
### otherwise just use duo or google two step auth.
