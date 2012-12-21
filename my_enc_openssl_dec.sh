./my_rsakeygen private public
sleep 3
./rsa_engine -e -k public.der test_3.txt test_3.enc
sleep 2
openssl rsa -inform DER -in private.der -outform PEM -out private.pem
sleep 2
openssl rsa -inform DER -in private.der -outform PEM -pubout -out public.pem
sleep 2
openssl rsautl -decrypt -inkey private.pem -in test_3.enc -out test_3.dec
sleep 2
diff test_3.txt test_3.dec