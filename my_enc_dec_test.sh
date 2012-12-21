./my_rsakeygen private public
sleep 5
./rsa_engine -e -k public.der test_1.txt test_1.enc
sleep 3
./rsa_engine -d -k private.der test_1.enc test_1.dec
sleep 3
diff test_1.txt test_1.dec
