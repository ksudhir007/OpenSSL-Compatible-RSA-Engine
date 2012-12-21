./my_rsakeygen private public
sleep 3
openssl rsa -inform DER -in private.der -outform PEM -out private.pem
sleep 2
openssl rsa -inform DER -in private.der -outform PEM -pubout -out public.pem
sleep 2
openssl rsautl -encrypt -inkey public.pem -pubin -in test_2.txt -out test_2.enc
sleep 2
openssl rsautl -decrypt -inkey private.pem -in test_2.enc -out test_2.dec
sleep 2
diff test_2.txt test_2.dec

