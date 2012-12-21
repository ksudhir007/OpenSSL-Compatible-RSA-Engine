./my_rsakeygen private public
sleep 3
openssl rsa -inform DER -in private.der -outform PEM -out private.pem
sleep 2
openssl rsa -inform DER -in private.der -outform PEM -pubout -out public.pem
sleep 2
openssl rsautl -encrypt -inkey public.pem -pubin -in test_4.txt -out test_4.enc
sleep 2
./rsa_engine -d -k private.der test_4.enc test_4.dec
sleep 3
diff test_4.txt test_4.dec
