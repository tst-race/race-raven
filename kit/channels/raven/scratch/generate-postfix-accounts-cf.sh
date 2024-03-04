# a script to generate a bunch of postfix accounts

# it may be easiest to run this within rib

DOMAIN=racemail-raven.test
PASS=pass1234

mkdir -p config/

for i in {001..500}
do
    echo "on iteration $i"
    docker run --rm   -e MAIL_USER=race-client-00${i}@${DOMAIN}   -e MAIL_PASS=${PASS}   -it mailserver/docker-mailserver:latest   /bin/sh -c 'echo "$MAIL_USER|$(doveadm pw -s SHA512-CRYPT -u $MAIL_USER -p $MAIL_PASS)"' >> config/postfix-accounts.cf
    docker run --rm   -e MAIL_USER=race-server-00${i}@${DOMAIN}   -e MAIL_PASS=${PASS}   -it mailserver/docker-mailserver:latest   /bin/sh -c 'echo "$MAIL_USER|$(doveadm pw -s SHA512-CRYPT -u $MAIL_USER -p $MAIL_PASS)"' >> config/postfix-accounts.cf
done
