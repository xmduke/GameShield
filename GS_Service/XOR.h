#pragma once

class _XOR
{

private:

	std::string Key;

public:
	
	_XOR() 
	{
		this->Key = "";
	}
	
	void Encrypt()
	{
		//Encryption routine
		if (this->Encrypted.size())
			this->Encrypted.clear();

		this->Encrypted = this->msg;

		for (unsigned int i = 0; i < this->msg.size(); i++)
		{
			this->Encrypted[i] = this->msg[i] ^ this->Key[i];
		}
	}

	void Decrpyt()
	{
		//Decryption routine
		if (this->Decrypted.size())
			this->Decrypted.clear();

		this->Decrypted = this->Encrypted;

		if (this->Encrypted.size())
		{
			for (unsigned int i = 0; i < this->Encrypted.size(); i++)
			{
				this->Decrypted[i] = this->Encrypted[i] ^ this->Key[i];
			}
		}
		else
		{
			printf("[XOR] Encrypted string is not provided\n");
		}
	}

	std::string GenKey(size_t length)
	{
		auto randchar = []() -> char
		{
			const char charset[] =
				"0123456789"
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				"abcdefghijklmnopqrstuvwxyz";
			const size_t max_index = (sizeof(charset) - 1);
			return charset[rand() % max_index];
		};
		std::string str(length, 0);
		std::generate_n(str.begin(), length, randchar);
		return str;
	}

	bool AssignKey()
	{
		if (!this->msg.size())
		{
			printf("[XOR] Please provide a valid Message first\n");
			return false;
		}

		int msgSize = this->msg.size(); //Get Size of string
		
		this->Key = GenKey(msgSize);

		if (this->Key.size() != msgSize)
		{
			printf("[XOR] Key %s not valid\n", this->Key.c_str());
			return false;
		}

		printf("[XOR] Key used: %s\n\n", this->Key.c_str());
		return true;
	}


	std::string msg;
	std::string Encrypted;
	std::string Decrypted;
};