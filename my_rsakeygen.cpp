#include <iostream>
#include <fstream>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <gmp.h>
#include <fcntl.h>
#include <vector>

using namespace std;

#define MODULUS_SIZE 1024                  /* This is the number of bits we want in the modulus */
#define BLOCK_SIZE (MODULUS_SIZE/8)         /* This is the size of a block that gets en/decrypted at once */
#define BUFFER_SIZE ((MODULUS_SIZE/8) / 2)  /* This is the number of bytes in n and p */

string key_header = "30";
string algorithm = "020100";
string public_header_const = "300d06092a864886f70d010101050003818b00308187";

typedef struct {
    mpz_t n; /* Modulus */
    mpz_t e; /* Public Exponent */
} public_key;

typedef struct {
    mpz_t n; /* Modulus */
    mpz_t e; /* Public Exponent */
    mpz_t d; /* Private Exponent */
    mpz_t p; /* Starting prime p */
    mpz_t q; /* Starting prime q */
    mpz_t e_1; /* Exponent 1*/
    mpz_t e_2; /* Exponent 2 */
    mpz_t c; /* Cofficient*/
} private_key;

int hex_to_int(string hexValue)
{
   int hexNumber;
   sscanf(hexValue.c_str(), "%02x", &hexNumber);
   return hexNumber;
}

vector<string> splitString(char* input)
{
    vector<string> myList;
    int count = 2;
    int index = 0;
    int indexTemp = 0;
    char temp[2];
    
    for(int i=0; i<strlen(input); i++)
    {
        if(index < 2)
        {
            temp[indexTemp++] = input[i];
            index++;
        }
        if(index==2)
        {
            myList.push_back(temp);
            index=0;
            indexTemp=0;
        }
    }
    return myList;
}

string prepare_tlv_string(unsigned int length, string toAppend, char* type)
{
    string toReturn;
    int temp, type_in_tlv;
    char temp_char;
    int appendZero = 0;

    if (length % 2 != 0)
    {
        toAppend = "0" + toAppend;
        length = length + 1;
    }

    if (type == "int")
        type_in_tlv = 2;
    else if(type == "seq")
        type_in_tlv = 30;

    temp_char = (char)toAppend[0];
    if (isdigit(temp_char))
    {
        if(atoi(&temp_char) > 7)
            appendZero = 1;
    }
    else
        appendZero = 1;
 
    if(length/2 < 128)
    {
        char buff[2];
        sprintf(buff, "%02x", type_in_tlv);
        toReturn += buff;
        if(appendZero == 1)
        {
            sprintf(buff, "%02x", (length/2) + 1);
            toReturn += buff;

            sprintf(buff, "%02x", 0);
            toReturn += buff;
        }
        else
        {
            sprintf(buff, "%02x", (length/2));
            toReturn += buff;

        }
        toReturn += toAppend;
        return toReturn;
    }
    else if((length/2 >= 128) && (length/2 < 256))
    {
        char buff[2];
        sprintf(buff, "%02x", type_in_tlv);
        toReturn += buff;
        sprintf(buff, "%02x", 129);
        toReturn += buff;
        if(appendZero == 1)
        {
            sprintf(buff, "%02x", (length/2) + 1);
            toReturn += buff;

            sprintf(buff, "%02x", 0);
            toReturn += buff;
        }
        else
        {
            sprintf(buff, "%02x", (length/2));
            toReturn += buff;

        }
        toReturn += toAppend;
        return toReturn;
    }
    else if(length/2 >= 256)
    {
        char buff[2];
        sprintf(buff, "%02x", type_in_tlv);
        toReturn += buff;
        sprintf(buff, "%02x", 130);
        toReturn += buff;
        if(appendZero == 1)
        {
            sprintf(buff, "%04x", (length/2) + 1);
            toReturn += buff;

            sprintf(buff, "%02x", 0);
            toReturn += buff;
        }
        else
        {
            sprintf(buff, "%04x", (length/2));
            toReturn += buff;

        }
        toReturn += toAppend;
        return toReturn;
    }

}

void generate_keys(private_key* ku, public_key* kp)
{
    char buf[BUFFER_SIZE];
    int i;
    mpz_t phi; mpz_init(phi);
    mpz_t tmp1; mpz_init(tmp1);
    mpz_t tmp2; mpz_init(tmp2);
    mpz_t pminus1; mpz_init(pminus1);
    mpz_t qminus1; mpz_init(qminus1);

    srand(time(NULL));

    /* Insetead of selecting e st. gcd(phi, e) = 1; 1 < e < phi, lets choose e
     * first then pick p,q st. gcd(e, p-1) = gcd(e, q-1) = 1 */
    // We'll set e globally.  I've seen suggestions to use primes like 3, 17 or 
    // 65537, as they make coming calculations faster.  Lets use 3.
    mpz_set_ui(ku->e, 3); 

    /* Select p and q */
    /* Start with p */
    // Set the bits of tmp randomly
    for(i = 0; i < BUFFER_SIZE; i++)
        buf[i] = rand() % 0xFF; 
    // Set the top two bits to 1 to ensure int(tmp) is relatively large
    buf[0] |= 0xC0;
    // Set the bottom bit to 1 to ensure int(tmp) is odd (better for finding primes)
    buf[BUFFER_SIZE - 1] |= 0x01;
    // Interpret this char buffer as an int
    mpz_import(tmp1, BUFFER_SIZE, 1, sizeof(buf[0]), 0, 0, buf);
    // Pick the next prime starting from that random number
    mpz_nextprime(ku->p, tmp1);
    /* Make sure this is a good choice*/
    mpz_mod(tmp2, ku->p, ku->e);        /* If p mod e == 1, gcd(phi, e) != 1 */
    while(!mpz_cmp_ui(tmp2, 1))         
    {
        mpz_nextprime(ku->p, ku->p);    /* so choose the next prime */
        mpz_mod(tmp2, ku->p, ku->e);
    }

    /* Now select q */
    do {
        for(i = 0; i < BUFFER_SIZE; i++)
            buf[i] = rand() % 0xFF; 
        // Set the top two bits to 1 to ensure int(tmp) is relatively large
        buf[0] |= 0xC0;
        // Set the bottom bit to 1 to ensure int(tmp) is odd
        buf[BUFFER_SIZE - 1] |= 0x01;
        // Interpret this char buffer as an int
        mpz_import(tmp1, (BUFFER_SIZE), 1, sizeof(buf[0]), 0, 0, buf);
        // Pick the next prime starting from that random number
        mpz_nextprime(ku->q, tmp1);
        mpz_mod(tmp2, ku->q, ku->e);
        while(!mpz_cmp_ui(tmp2, 1))
        {
            mpz_nextprime(ku->q, ku->q);
            mpz_mod(tmp2, ku->q, ku->e);
        }
    } while(mpz_cmp(ku->p, ku->q) == 0); /* If we have identical primes (unlikely), try again */

    /* make p > q */
    if (mpz_cmp(ku->p, ku->q) < 0)
        mpz_swap(ku->p, ku->q);

    /* Calculate n = p x q */
    mpz_mul(ku->n, ku->p, ku->q);

    /* Compute phi(n) = (p-1)(q-1) */
    mpz_sub_ui(tmp1, ku->p, 1);
    mpz_sub_ui(tmp2, ku->q, 1);
    mpz_mul(phi, tmp1, tmp2);

    /* Calculate d (multiplicative inverse of e mod phi) */
    if(mpz_invert(ku->d, ku->e, phi) == 0)
    {
        mpz_gcd(tmp1, ku->e, phi);
        printf("gcd(e, phi) = [%s]\n", mpz_get_str(NULL, 16, tmp1));
        printf("Invert failed\n");
    }

    /* Set public key */
    mpz_set(kp->e, ku->e);
    mpz_set(kp->n, ku->n);


    /* Compute exponent 1, exponent 2 and coefficient */

    mpz_sub_ui(pminus1, ku->p, 1);
    mpz_sub_ui(qminus1, ku->q, 1);
 
    mpz_mod(ku->e_1, ku->d, pminus1);
    mpz_mod(ku->e_2, ku->d, qminus1);
 
    /* Chinese remainder theorem coefficient (inverse of q mod p) */
    mpz_invert(ku->c, ku->q, ku->p);

    /* If coefficient is negative, then add p to make it positive */
    if (mpz_sgn(ku->c) == -1) 
    {
        mpz_add(ku->c, ku->c, ku->p);
    } 

    return;
}
#if 0
void write_pem_files(string der_file_to_read, string file_to_write, string header)
{
    int size;
    char *memblock;
    char *header_string;
    char *footer_string;
    vector<string> byte_vector;

    ifstream file(const_cast<char*>(der_file_to_read.c_str()), ios::in|ios::binary|ios::ate);
    if (file.is_open())
    {
        size = file.tellg();
        memblock = new char[size];
        memset(memblock, 0, size);
        file.seekg (0, ios::beg);
        file.read (memblock, size);
        file.close();
    }

    char *encoded_string = new char[1024];
    memset(encoded_string, 0, 1024);
    int return_value = base64encode(memblock, size, encoded_string);

    if (return_value != 0)
    {
        cout<<"base64encode error!!"<<endl;
        exit(0);
    }

    int pFile;
    pFile = open (const_cast<char*>(file_to_write.c_str()), O_WRONLY | O_CREAT | O_TRUNC);

    if(pFile != -1)
    {
        if (header == "PRIVATE")
            write(pFile, "-----BEGIN RSA PRIVATE KEY-----", 31);
        else if (header == "PUBLIC")
            write(pFile, "-----BEGIN PUBLIC KEY-----", 26);

        write(pFile, "\n", 1);

        int counter = 0;
        for(int i = 0; i < strlen(encoded_string); i++, counter++)
        {
            if (counter == 64)
            {
                write(pFile, "\n", 1);
                counter = 0;
            }
            write(pFile, (const char*)&encoded_string[i], 1);
        }
        write(pFile, "\n", 1);
        if (header == "PRIVATE")
            write(pFile, "-----END RSA PRIVATE KEY-----", 29);
        else if (header == "PUBLIC")
            write(pFile, "-----END PUBLIC KEY-----", 24);
        write(pFile, "\n", 1);

        close(pFile);
    }

    delete [] memblock;
    delete [] encoded_string;
    return;
}
#endif 

int main(int argc, char** argv) 
{
    private_key ku;
    public_key kp;

    if (argc != 3)
    {
        cout<<"Usage: ./my_rsakeygen <filename for private key> <filename for public key>" <<endl;
        cout<<"Please enter just file names, without extensions."<<endl;
        cout<<"Both DER and PEM formats will be written with appropriate extensions."<<endl;
        exit(0);
    }

    string temp1(argv[1]);
    string temp2(argv[2]);
    string der_private_key_file_name = temp1 + const_cast<char*>(".der");
    string der_public_key_file_name = temp2 + const_cast<char*>(".der");
    string pem_private_key_file_name = temp1 + const_cast<char*>(".pem");
    string pem_public_key_file_name = temp2 + const_cast<char*>(".pem");

    // Initialize public key
    mpz_init(kp.n);
    mpz_init(kp.e); 
    // Initialize private key
    mpz_init(ku.n); 
    mpz_init(ku.e); 
    mpz_init(ku.d); 
    mpz_init(ku.p); 
    mpz_init(ku.q); 
    mpz_init(ku.e_1);
    mpz_init(ku.e_2);
    mpz_init(ku.c);

    generate_keys(&ku, &kp);

    int kp_modulus_length = strlen(mpz_get_str(NULL, 16, kp.n));
    int kp_public_exponent = strlen(mpz_get_str(NULL, 16, kp.e));
    int ku_modulus_length = strlen(mpz_get_str(NULL, 16, ku.n));
    int ku_public_exponent = strlen(mpz_get_str(NULL, 16, ku.e));
    int ku_private_exponent = strlen(mpz_get_str(NULL, 16, ku.d));
    int ku_prime1 = strlen(mpz_get_str(NULL, 16, ku.p));
    int ku_prime2 = strlen(mpz_get_str(NULL, 16, ku.q));
    int ku_exp1 = strlen(mpz_get_str(NULL, 16, ku.e_1));
    int ku_exp2 = strlen(mpz_get_str(NULL, 16, ku.e_2));
    int ku_coeff = strlen(mpz_get_str(NULL, 16, ku.c));
    
    // cout<<algorithm<<endl;

    string modulus_value;
    modulus_value = prepare_tlv_string(kp_modulus_length, mpz_get_str(NULL, 16, kp.n), const_cast<char*>("int"));
    // cout<<kp_modulus_length<<endl<<modulus_value<<endl;

    string public_exponent;
    public_exponent = prepare_tlv_string(kp_public_exponent, mpz_get_str(NULL, 16, kp.e), const_cast<char*>("int"));
    // cout<<kp_public_exponent<<endl<<public_exponent<<endl;

    string private_exponent;
    private_exponent = prepare_tlv_string(ku_private_exponent, mpz_get_str(NULL, 16, ku.d), const_cast<char*>("int"));
    // cout<<private_exponent<<endl;

    string prime1;
    prime1 = prepare_tlv_string(ku_prime1, mpz_get_str(NULL, 16, ku.p), const_cast<char*>("int"));
    // cout<<prime1<<endl;

    string prime2;
    prime2 = prepare_tlv_string(ku_prime2, mpz_get_str(NULL, 16, ku.q), const_cast<char*>("int"));
    // cout<<prime2<<endl;

    string exp_1;
    exp_1 = prepare_tlv_string(ku_exp1, mpz_get_str(NULL, 16, ku.e_1), const_cast<char*>("int"));
    // cout<<exp_1<<endl;

    string exp_2;
    exp_2 = prepare_tlv_string(ku_exp2, mpz_get_str(NULL, 16, ku.e_2), const_cast<char*>("int"));
    // cout<<exp_2<<endl;

    string coeff;
    coeff = prepare_tlv_string(ku_coeff, mpz_get_str(NULL, 16, ku.c), const_cast<char*>("int"));
    // cout<<coeff<<endl;

    string whole_private_pdu;
    string temp_pdu = algorithm + modulus_value + public_exponent + private_exponent + prime1 + prime2 + exp_1 + exp_2 + coeff;

    temp_pdu = prepare_tlv_string(temp_pdu.length(), const_cast<char*>(temp_pdu.c_str()), const_cast<char*>("seq"));
    whole_private_pdu = key_header + temp_pdu.substr(2, temp_pdu.length());


    ofstream my_private_derfile;
    cout<<"Writing private key : " << const_cast<char*>(der_private_key_file_name.c_str()) <<endl;
    my_private_derfile.open(const_cast<char*>(der_private_key_file_name.c_str()));
    int value_byte = 0;
    vector<string> private_toIterate = splitString(const_cast<char*>(whole_private_pdu.c_str()));

    for (vector<string>::iterator i = private_toIterate.begin();i != private_toIterate.end();i++)
    {
        value_byte = hex_to_int(*i);
        my_private_derfile << (unsigned char)value_byte;
    }

    my_private_derfile.close();
    cout<<"Finished writing private key : "<< const_cast<char*>(der_private_key_file_name.c_str()) <<endl;
    cout<<"-----------------------------------------------------------------------"<<endl;

    string whole_public_pdu;
    string temp_public_pdu = public_header_const + modulus_value + public_exponent;
    temp_public_pdu = prepare_tlv_string(temp_public_pdu.length(), const_cast<char*>(temp_public_pdu.c_str()), const_cast<char*>("seq"));
    whole_public_pdu = key_header + temp_public_pdu.substr(2, temp_public_pdu.length());

    ofstream my_public_derfile;
    cout<<"Writing public key : "<<const_cast<char*>(der_public_key_file_name.c_str())<<endl;
    my_public_derfile.open(const_cast<char*>(der_public_key_file_name.c_str()));
    value_byte = 0;
    vector<string> public_toIterate = splitString(const_cast<char*>(whole_public_pdu.c_str()));

    int skipper_00_public = 0;
    for (vector<string>::iterator i = public_toIterate.begin();i != public_toIterate.end();i++, skipper_00_public++)
    {
        if(skipper_00_public == 3)
            continue;
        value_byte = hex_to_int(*i);
        my_public_derfile << (unsigned char)value_byte;
    }

    my_public_derfile.close();    
    cout<<"Finished writing public key : "<< const_cast<char*>(der_public_key_file_name.c_str())<<endl;
    cout<<"-----------------------------------------------------------------------"<<endl;
#if 0
    cout<<"Writing private key in pem format. "<<endl;
    write_pem_files(der_private_key_file_name, pem_private_key_file_name, "PRIVATE");
    cout<<"Finished writing private key in pem format. "<<endl;
    cout<<"Writing public key in pem format. "<<endl;
    write_pem_files(der_public_key_file_name, pem_public_key_file_name, "PUBLIC");
    cout<<"Finished writing public key in pem format."<<endl;
#endif
    exit(0);
}
