#include "libs/hmac.c"
#include "libs/sha1.c"

#include <stdlib.h>
#include <stdio.h>
#include <time.h>



static inline int parseUUID(const char* _Str, uint8_t _Data[16])
{
	int length = strlen(_Str);

	const char* ptr = _Str;
	unsigned int currentValue;
	unsigned int i = 0;
	
	while(*(ptr) != 0 && *(ptr + 1) != 0 && (length <= 0 || (ptr - _Str) < length) && i < 16)
	{
		if(*(ptr) == '-')
		{
			ptr++;
		}
		else
		{
			if(sscanf((const char*)ptr, "%02x", &currentValue) != 1)
			{
				return -1;
			}
			else
			{
				_Data[i] = (uint8_t)currentValue;
				ptr += 2;
				i++;
			}
		}
	}
	
	
	return i;
}

int main()
{
	uint64_t systemTime = 1475226019lu; //time(NULL);
	const char* clientID = "9818d49a-005d-4a83-93b3-9de04a6a5225";
	const char* method = "GetCustomerData";

	const char* clientKey = "5878b222-9781-4e1b-936f-ef9ccad60518";

	char message[512];
	sprintf(message, "%lu%s%s", systemTime, clientID, method);

	uint8_t key[16];
	parseUUID(clientKey, key);


	uint8_t hash[SHA1_DIGEST_LENGTH];
	memset(hash, 0, sizeof(hash));
	hmac_sha1(key, sizeof(key), (const uint8_t*)message, strlen(message), hash, sizeof(hash));

	char clientToken[64];
	char* ptr = clientToken;
	for(int i = 0; i < SHA1_DIGEST_LENGTH; i++)
		ptr += sprintf(ptr, "%02x", hash[i]);


	printf("systemTime: \"%lu\"\r\n", systemTime);
	printf("clientID: \"%s\"\r\n", clientID);
	printf("method: \"%s\"\r\n", method);
	printf("clientKey: \"%s\"\r\n", clientKey);
	printf("message: \"%s\"\r\n", message);
	printf("clientToken: \"%s\"\r\n", clientToken);



	return 0;
}
