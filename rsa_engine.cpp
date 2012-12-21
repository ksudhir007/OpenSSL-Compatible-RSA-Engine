#include <iostream>
#include <fstream>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <gmp.h>
#include <fcntl.h>
#include <vector>

#define MODULUS_SIZE 1024                  /* This is the number of bits we want in the modulus */
#define BLOCK_SIZE (MODULUS_SIZE/8)         /* This is the size of a block that gets en/decrypted at once */
#define BUFFER_SIZE ((MODULUS_SIZE/8) / 2)  /* This is the number of bytes in n and p */

using namespace std;

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

typedef struct 
{
  unsigned char seperator;
  unsigned char length_indicator;
  int length;
  unsigned char value[1024];
}my_tlv_packet;

typedef struct options_struct{
	int  encryptFlag, decryptFlag, keyFlag;
	char *key_input, *inputFile, *outputFile;
} options;

private_key loaded_private_key;
public_key loaded_public_key;

int hex_to_int(std::string hexValue)
{
   int hexNumber;
   sscanf(hexValue.c_str(), "%x", &hexNumber);
   return hexNumber;
}

int parse_options(options *opts, int argc, char **argv)
{
	int opt_char, errFlag;
	errFlag = 0;

	while ((opt_char = getopt(argc, argv, "edk:h")) != -1){
		switch(opt_char){
		case 'e':
			opts->encryptFlag = 1;
			break;
		case 'd':
			opts->decryptFlag = 1;
			break;
		case 'k':
			opts->keyFlag = 1;
			opts->key_input = optarg;
			break;
		case 'h':
			fprintf(stdout, "Usage: %s {-e|-d} {-k KEY FILE} [-h HELP] infile outfile\n", argv[0]);
			fprintf(stdout, "{-e|-d} : Use either -e to encrypt OR -d to decrypt.\n");
      fprintf(stdout, "-k : Use to give key file. Only DER format is supported. Ex: -k \"public.der\"\n");
			fprintf(stdout, "-h : Use to display this help message\n");
			fprintf(stdout, "infile : Use to specify input file name (along with path)\n");
			fprintf(stdout, "outfile : Use to specify output file name (along with path)\n"); 
			return -1;
		default: 
			errFlag = 1;
		}
	}

	if ((opts->encryptFlag == opts->decryptFlag) || (1 == errFlag) || 
	(0 == opts->keyFlag) || (optind + 2 != argc)){
		fprintf(stderr, "Usage: %s {-e|-d} {-k KEY FILE} [-h HELP] infile outfile\n", argv[0]);
		return -1;
	}else{
		opts->inputFile = argv[optind];
		opts->outputFile = argv[optind + 1];
		return 0;
	}
}

int unpack_tlv_packet(unsigned char* input_der, int input_size, int starting_index, unsigned char sequence,
                             unsigned char next_sequence, my_tlv_packet *result, int value_required)
{
    
    unsigned char temp[2048];
    
    for(int i = 0; i < sizeof(temp); i++){
        temp[i] = 0;
    }
    
    for(int i = 0; i < input_size; i++){
        temp[i] = input_der[i];
    }
    
    result->seperator = temp[starting_index];
    result->length_indicator = (size_t)temp[starting_index + 1];
    
    starting_index = starting_index + 1;
    
    if(result->length_indicator <= 0x80){
        result->length = (size_t)result->length_indicator;
        starting_index = starting_index + 1;
    }
    else if(result->length_indicator > 128 && result->length_indicator <= 256){
        
        if(result->length_indicator == 0x81){
            result->length = (size_t)temp[starting_index + 1];
            starting_index = starting_index + 2;
        }
        else if(result->length_indicator == 0x82){
            char *tmp = (char*)malloc(4);
            sprintf(tmp, "%.02x%.02x\n", temp[starting_index + 1], temp[starting_index + 2]);
            result->length = hex_to_int(tmp);
            starting_index = starting_index + 3;
        }
    }
    else if(result->length_indicator > 256){
        starting_index = starting_index + 4;
    }
    if(value_required == 1){
        for(size_t j = 0; j < result->length; j++){
            result->value[j] = temp[starting_index];
            starting_index = starting_index + 1;
        }
        if(temp[starting_index] == next_sequence){
        }
    }
    else if(value_required == 0){
        if(temp[starting_index] == next_sequence){
        }
        return starting_index;
    }
    
    
    return starting_index;
}

int load_private_into_mpz(unsigned char* input_der, int input_der_length)
{

#if 0
  for(int i = 0; i < input_der_length; i++)
    printf("%02x ",input_der[i]);
  printf("\n");     
#endif

  my_tlv_packet header;
  memset(&header, 0, sizeof(header));
  int offset = unpack_tlv_packet(input_der, input_der_length, 0, 0x30, 0x02, &header, 0);

  my_tlv_packet algorithm_version;
  memset(&algorithm_version, 0, sizeof(algorithm_version));
  offset = unpack_tlv_packet(input_der, input_der_length, offset, 0x02, 0x02, &algorithm_version, 1);

  my_tlv_packet modulus;
  memset(&modulus, 0, sizeof(modulus));
  offset = unpack_tlv_packet(input_der, input_der_length, offset, 0x02, 0x02, &modulus, 1);

  my_tlv_packet public_exponent;
  memset(&public_exponent, 0, sizeof(public_exponent));
  offset = unpack_tlv_packet(input_der, input_der_length, offset, 0x02, 0x02, &public_exponent, 1);  

  my_tlv_packet private_exponent;
  memset(&private_exponent, 0, sizeof(private_exponent));
  offset = unpack_tlv_packet(input_der, input_der_length, offset, 0x02, 0x02, &private_exponent, 1);  

  my_tlv_packet prime_1;
  memset(&prime_1, 0, sizeof(prime_1));
  offset = unpack_tlv_packet(input_der, input_der_length, offset, 0x02, 0x02, &prime_1, 1);  

  my_tlv_packet prime_2;
  memset(&prime_2, 0, sizeof(prime_2));
  offset = unpack_tlv_packet(input_der, input_der_length, offset, 0x02, 0x02, &prime_2, 1);  

  my_tlv_packet exp_1;
  memset(&exp_1, 0, sizeof(exp_1));
  offset = unpack_tlv_packet(input_der, input_der_length, offset, 0x02, 0x02, &exp_1, 1);  

  my_tlv_packet exp_2;
  memset(&exp_2, 0, sizeof(exp_2));
  offset = unpack_tlv_packet(input_der, input_der_length, offset, 0x02, 0x02, &exp_2, 1);   

  my_tlv_packet coefficient;
  memset(&coefficient, 0, sizeof(coefficient));
  offset = unpack_tlv_packet(input_der, input_der_length, offset, 0x02, 0x00, &coefficient, 1);  

  // Initialize private key
  mpz_init(loaded_private_key.n); 
  mpz_init(loaded_private_key.e); 
  mpz_init(loaded_private_key.d); 
  mpz_init(loaded_private_key.p); 
  mpz_init(loaded_private_key.q); 
  mpz_init(loaded_private_key.e_1);
  mpz_init(loaded_private_key.e_2);
  mpz_init(loaded_private_key.c);
  mpz_import(loaded_private_key.n, modulus.length, 1, 1, 0, 0, modulus.value);
  mpz_import(loaded_private_key.e, public_exponent.length, 1, 1, 0, 0, public_exponent.value);
  mpz_import(loaded_private_key.d, private_exponent.length, 1, 1, 0, 0, private_exponent.value);
  mpz_import(loaded_private_key.p, prime_1.length, 1, 1, 0, 0, prime_1.value);
  mpz_import(loaded_private_key.q, prime_2.length, 1, 1, 0, 0, prime_2.value);
  mpz_import(loaded_private_key.e_1, exp_1.length, 1, 1, 0, 0, exp_1.value);
  mpz_import(loaded_private_key.e_2, exp_2.length, 1, 1, 0, 0, exp_2.value);
  mpz_import(loaded_private_key.c, coefficient.length, 1, 1, 0, 0, coefficient.value);


#if 0  
    printf("---------------Private Key------------------\n");
    printf("ku.n length [%d] is [%s]\n", strlen(mpz_get_str(NULL, 16, loaded_private_key.n)) ,mpz_get_str(NULL, 16, loaded_private_key.n));
    printf("ku.e length [%d] is [%s]\n", strlen(mpz_get_str(NULL, 16, loaded_private_key.e)) ,mpz_get_str(NULL, 16, loaded_private_key.e));
    printf("ku.d length [%d] is [%s]\n", strlen(mpz_get_str(NULL, 16, loaded_private_key.d)) ,mpz_get_str(NULL, 16, loaded_private_key.d));
    printf("ku.p length [%d] is [%s]\n", strlen(mpz_get_str(NULL, 16, loaded_private_key.p)) ,mpz_get_str(NULL, 16, loaded_private_key.p));
    printf("ku.q length [%d] is [%s]\n", strlen(mpz_get_str(NULL, 16, loaded_private_key.q)) ,mpz_get_str(NULL, 16, loaded_private_key.q));
    printf("ku.e_1 length [%d] is [%s]\n", strlen(mpz_get_str(NULL, 16, loaded_private_key.e_1)) ,mpz_get_str(NULL, 16, loaded_private_key.e_1));
    printf("ku.e_2 length [%d] is [%s]\n", strlen(mpz_get_str(NULL, 16, loaded_private_key.e_2)) ,mpz_get_str(NULL, 16, loaded_private_key.e_2));
    printf("ku.c length [%d] is [%s]\n", strlen(mpz_get_str(NULL, 16, loaded_private_key.c)) ,mpz_get_str(NULL, 16, loaded_private_key.c));
#endif 

  return 0;
}

int load_public_into_mpz(unsigned char* input_der, int input_der_length)
{

#if 0
  for(int i = 0; i < input_der_length; i++)
    printf("%02x ",input_der[i]);
  printf("\n");     
#endif

  int offset;
#if 1
  my_tlv_packet header1;
  memset(&header1, 0, sizeof(header1));
  offset = unpack_tlv_packet(input_der, input_der_length, 0, 0x30, 0x30, &header1, 0);

  //cout << offset <<endl;

  my_tlv_packet trash_this;
  memset(&trash_this, 0, sizeof(trash_this));
  offset = unpack_tlv_packet(input_der , input_der_length, offset, 0x30, 0x03, &trash_this, 1);   

  //cout << offset<<endl; 
#endif

#if 0
    printf(" See this one %02x \n ",input_der[offset + 13]);
#endif    

  my_tlv_packet modulus;
  memset(&modulus, 0, sizeof(modulus));
  offset = unpack_tlv_packet(input_der, input_der_length, offset + 13, 0x02, 0x02, &modulus, 1);

#if 0
    printf("%02x ",input_der[offset]);
#endif

  my_tlv_packet public_exponent;
  memset(&public_exponent, 0, sizeof(public_exponent));
  offset = unpack_tlv_packet(input_der, input_der_length, offset, 0x02, 0x00, &public_exponent, 1);  

  // Initialize public key
  mpz_init(loaded_public_key.n); 
  mpz_init(loaded_public_key.e); 

  mpz_import(loaded_public_key.n, modulus.length, 1, 1, 0, 0, modulus.value);
  mpz_import(loaded_public_key.e, public_exponent.length, 1, 1, 0, 0, public_exponent.value);

#if 0
  printf("---------------Public Key-----------------\n");
  printf("kp.n length [%d] is [%s]\n", strlen(mpz_get_str(NULL, 16, loaded_public_key.n)) ,mpz_get_str(NULL, 16, loaded_public_key.n));
  printf("kp.e length [%d] is [%s]\n", strlen(mpz_get_str(NULL, 16, loaded_public_key.e)) ,mpz_get_str(NULL, 16, loaded_public_key.e));
#endif 

  return 0;
}

void read_key_der_file(string file_name, string key_type)
{
  char *memblock;
  int size;
  std::ifstream file(const_cast<char*>(file_name.c_str()), ios::in|ios::binary|ios::ate);
  if (file.is_open())
  {

      size = file.tellg();
      memblock = new char [size];
      file.seekg (0, ios::beg);
      file.read (memblock, size);
      file.close();

      if (key_type == "PRIVATE")
        load_private_into_mpz((unsigned char*)(memblock), size);
      else if (key_type == "PUBLIC")
        load_public_into_mpz((unsigned char*)(memblock), size);
      delete[] memblock;
  }
}

unsigned char generate_non_zero_random_byte()
{
    unsigned char your_buffer;

    int fd = open("/dev/urandom", O_RDONLY);
    read(fd, &your_buffer, sizeof(unsigned char));
    close(fd);

    if (your_buffer == 0)
        your_buffer = your_buffer | 0xFF;

    return your_buffer;
}

int rsa_encrypt(mpz_t n, mpz_t e, char* message, int messageLength, unsigned char** cipher_message, size_t& cipher_length)
{

    if (messageLength > BLOCK_SIZE - 11)
    {
        cout<<"Input too long. Better luck next time! "<< endl;
        return -1;
    }
    /* Prepare the encoded message */
    unsigned char* encoded_message = new unsigned char[MODULUS_SIZE/8];
    memset(encoded_message, 0, MODULUS_SIZE/8);

    unsigned char* actual_message = new unsigned char[messageLength];
    memset(actual_message, 0, messageLength);

    memcpy(actual_message, message, messageLength);

    unsigned char zero_byte = 0;
    unsigned char two_byte = 2;

    memcpy(encoded_message, &zero_byte, 1);
    memcpy(encoded_message + 1, &two_byte, 1);

    int padding_length = (MODULUS_SIZE/8) - messageLength - 3;
    /* Random octets of padding */
    for(int i = 0; i < padding_length; i++)
    {
        unsigned char temp_byte = generate_non_zero_random_byte();
        memcpy(encoded_message + 2 + i, &temp_byte, 1);
    }

    memcpy(encoded_message + padding_length + 2, &zero_byte, 1);
    memcpy(encoded_message + padding_length + 3, actual_message, messageLength);

#if 0
    cout<<"******* ACTUAL MESSAGE *************\n";
    for(int i = 0; i < messageLength; i++)
        printf("%02x ",actual_message[i]);
    printf("\n");

    cout << messageLength  << " -------- " << padding_length << endl;
    cout<<"******* ENCODED MESSAGE *************\n";
    for(int i = 0; i < MODULUS_SIZE/8; i++)
        printf("%02x ",encoded_message[i]);
    printf("\n");

#endif

    /* Do the encryption!! */
    mpz_t message_as_mpz, cipher_as_mpz;  

    mpz_init(message_as_mpz); 
    mpz_init(cipher_as_mpz); 
 
    mpz_import(message_as_mpz, MODULUS_SIZE/8, 1, sizeof(unsigned char), 0, 0, encoded_message); 
     
    mpz_powm(cipher_as_mpz, message_as_mpz, e, n); 
    unsigned char *cipher_temp = (unsigned char*)mpz_export(NULL, &cipher_length, 1, 1, 0, 0, cipher_as_mpz);

    *cipher_message = new unsigned char[cipher_length];
    memset(*cipher_message, 0, cipher_length);

    //memcpy(*cipher_message, cipher_temp, cipher_length); 
     
#if 1
    //cout<< "After encrypt" <<endl;
    for(int i = 0; i < MODULUS_SIZE/8; i++)
    {
        //printf("%02x ",cipher_temp[i]);
        memcpy(*cipher_message + i, cipher_temp + i, 1);
    }
#endif     

    mpz_clear(message_as_mpz); 
    mpz_clear(cipher_as_mpz);

    return 0; 
}

int rsa_decrypt(mpz_t n, mpz_t d, const unsigned char* cipher_message, int cipherLength, unsigned char** message , size_t& message_length)
{

    if (cipherLength != 128)
    {
      cout<<"Encypted file corrupted, not 128 bytes. Better luck next time. "<<endl;
      return -1; 
    }
    mpz_t cipher_as_mpz, message_as_mpz;
    mpz_init(cipher_as_mpz);
    mpz_init(message_as_mpz);

    mpz_import(cipher_as_mpz, MODULUS_SIZE/8, 1, sizeof(unsigned char), 0, 0, cipher_message); 
    mpz_powm(message_as_mpz, cipher_as_mpz, d, n); 
 
    size_t messageLength; 
    unsigned char* tempMsg= (unsigned char *)mpz_export(NULL,&messageLength,1,1,0,0,message_as_mpz); 

    unsigned char *message_to_finally_copy = new unsigned char[messageLength];
    memset(message_to_finally_copy, 0, messageLength);

    if (messageLength < MODULUS_SIZE/8)
        memcpy(message_to_finally_copy + 1, tempMsg, messageLength);
    else if (messageLength > MODULUS_SIZE/8)
        cout<<"Decryption failed.."<<endl;     

    message_length = messageLength;

#if 0
    cout<<"******* CIPHER MESSAGE *************\n";
    for(int i = 0; i < MODULUS_SIZE/8; i++)
        printf("%02x ",cipher_message[i]);
    printf("\n");

    cout<<"******* ENCODED MESSAGE *************\n";
    for(int i = 0; i < MODULUS_SIZE/8; i++)
        printf("%02x ",message_to_finally_copy[i]);
    printf("\n");

#endif

    int countNonZero =0;
    int i = 2;     

    if(message_to_finally_copy[0] != 0 && message_to_finally_copy[1] != 2)
    {
        cout<<"Decryption failed."<<endl;
        return -1;
    }
    else
    {
        for(i = 2; i < (MODULUS_SIZE/8); i++)
        {
            if (message_to_finally_copy[i] != 0x00)
                countNonZero++;
            else
            {   
                //cout << "finding zero " << i<<endl;
                break;
            }
        }
        if(countNonZero <= 8) 
        { 
            printf("Decryption Failed: Padding less than 8"); 
            return -1; 
        } 
    }

    //cout<< i << endl << (MODULUS_SIZE/8) - i << endl;

    *message = new unsigned char[(MODULUS_SIZE/8) - i];
    memset(*message, 0, (MODULUS_SIZE/8) - i);

#if 1
    for(int j = 0; j < (MODULUS_SIZE/8) - i; j++)
    {
        memcpy(*message + j, message_to_finally_copy + i + 1 + j, 1);
    }
#endif       

    message_length = (MODULUS_SIZE/8) - i;

    //printf("The length of the message = %d\n", message_length); 

    mpz_clear(message_as_mpz); 
    mpz_clear(cipher_as_mpz);    
    return 0;
    
}

int read_input_file(string file_name, char** bytes_to_encrypt, int& bytes_read)
{
  char *memblock;
  int size;
  std::ifstream file(const_cast<char*>(file_name.c_str()), ios::in|ios::binary|ios::ate);
  if (file.is_open())
  {

      size = file.tellg();
      memblock = new char [size];
      file.seekg (0, ios::beg);
      file.read (memblock, size);
      file.close();
      bytes_read = size;

      *bytes_to_encrypt = memblock;
      return 0;
  } 
  else
  {
    cout<< "Input file reading error."<<endl;
    return -1;
  } 
}

int write_output_file(string file_name, unsigned char* bytes_to_write, int length)
{
    ofstream myFile (const_cast<char*>(file_name.c_str()), ios::out | ios::binary);
    if (myFile.is_open())
    {
      myFile.write ((char*)bytes_to_write, length);
      myFile.close();
      return 0;
    }
    else
    {
      cout << "File write error."<< endl;
      return -1;
    }
}

int main(int argc, char *argv[])      
{
  options opts;
  int validOptions;
  memset(&opts, 0, sizeof opts);
  validOptions = parse_options(&opts,argc,argv);

  if(validOptions == 0)
  {
      if (opts.encryptFlag == 1)
        read_key_der_file(opts.key_input, "PUBLIC");
      if (opts.decryptFlag == 1)
        read_key_der_file(opts.key_input, "PRIVATE"); 

      int size_read;
      char* bytes_to_encrypt_or_decrypt;
      int return_value = read_input_file(opts.inputFile, &bytes_to_encrypt_or_decrypt, size_read);

      if (return_value == 0 && opts.encryptFlag == 1)
      {
          size_t cipher_length;
          unsigned char *cipher_message = NULL;
          return_value = rsa_encrypt(loaded_public_key.n, loaded_public_key.e, bytes_to_encrypt_or_decrypt, size_read, &cipher_message, cipher_length);
          
          if (return_value == 0)
          {
            return_value = write_output_file(opts.outputFile, cipher_message, cipher_length);
            if (return_value == 0)
              cout << "Encryption successful. Congrats!!" << endl;
            else
              cout << "Encryption failed. :(" <<endl;
          }
      }

      if (return_value == 0 && opts.decryptFlag == 1)
      {
          size_t message_length;
          unsigned char* message = NULL;
          return_value = rsa_decrypt(loaded_private_key.n, loaded_private_key.d, (unsigned char*)bytes_to_encrypt_or_decrypt, size_read, &message, message_length);

          if (return_value == 0)
          {
              return_value = write_output_file(opts.outputFile, message, message_length - 1);  
              if (return_value == 0)
                cout << "Decryption successful. Congrats!!" << endl;
              else
                cout << "Decryption failed. :(" <<endl;
          }
      }
  }
  exit(0);
}
