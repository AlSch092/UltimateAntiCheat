#pragma once
#include <Windows.h>
#include <string>
#include <iostream>     // std::cout, std::endl
#include <iomanip>      // std::setfill, std::setw
#include <stdint.h>
#include <sstream>

typedef uint16_t header_t;

class PacketWriter 
{
public:
	PacketWriter() : m_pos(0), m_buffer(new unsigned char[bufferLen]), m_length(bufferLen) { }
	PacketWriter(uint16_t h) : m_pos(0), m_buffer(new unsigned char[bufferLen]), m_length(bufferLen) { Write(h); }
	
	PacketWriter(const char* buff, int length) : m_pos(0), m_buffer(new unsigned char[length]), m_length(length)
	{ 
		for (int i = 0; i < length; i++)
			Write<BYTE>(buff[i]);
	}

	PacketWriter(uint16_t h, BYTE* bData, int length) : m_pos(0), m_buffer(new unsigned char[bufferLen]), m_length(bufferLen)
	{
		Write<uint16_t>(h);

		for (int i = 0; i < length; i++)
		{
			Write<byte>(bData[i]);
		}
	}

	~PacketWriter()
	{
		if (this->m_buffer != NULL)
			delete[] this->m_buffer;
	}

	void ReadString(std::string value);

	template<typename T>
	void Write(T value);
	template<typename T>
	void Fill(int times);
	void WriteString(const std::string& str); // Dynamically-lengthed strings
	void WriteString(const std::string& str, size_t len); // Static-lengthed strings
	void WriteWideString(const std::wstring& str, size_t len);
	void WriteNoLengthString(const std::string& str);
	void WriteZeros(int zeros);

	inline
		const unsigned char* GetBuffer() const {
		return m_buffer;
	}
	int GetSize() const { return m_pos; }
	std::string ToString() const;
private:
	static const size_t bufferLen = 1000; // Initial buffer length
	friend std::ostream& operator <<(std::ostream& out, const PacketWriter& packet); // Thanks, Bui!

	unsigned char* GetBuffer(int pos, int len);

	unsigned char* m_buffer;
	int m_pos, m_length;
};

template <typename T>
void PacketWriter::Write(T value) 
{
	(*(T*)GetBuffer(m_pos, +sizeof(T))) = value;
	m_pos += sizeof(T);
}


inline
std::ostream& operator <<(std::ostream& out, const PacketWriter& packet) 
{
	out << packet.ToString();
	return out;
}

inline
std::string PacketWriter::ToString() const 
{
	std::string ret;
	if (GetSize() > 0) {
		std::stringstream out;
		const unsigned char* p = GetBuffer();
		size_t buflen = GetSize() - 1;
		for (size_t i = 0; i <= buflen; i++) {
			out << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<int16_t>(p[i]);
			if (i < buflen) {
				out << " ";
			}
		}
		ret = out.str();
	}
	return ret;
}

inline
unsigned char* PacketWriter::GetBuffer(int pos, int len) 
{
	if (m_length < pos + len) 
	{
		// Buffer is not large enough
		while (m_length < pos + len) 
		{
			m_length *= 2; // Double the capacity each time the buffer is full
		}
		unsigned char* newBuffer = new unsigned char[m_length];
		memcpy(newBuffer, m_buffer, pos);
		m_buffer = newBuffer;
	}

	return m_buffer + pos;
}

inline
void PacketWriter::WriteString(const std::string& str, size_t len) 
{
	size_t slen = str.size();
	if (len < slen) 
	{
		throw std::invalid_argument("WriteString used with a length shorter than string size");
	}
	strncpy_s((char*)GetBuffer(m_pos, static_cast<int>(len)), len, str.c_str(), slen); //IF WE HAVE SOME ERROR, check to see if adding _s did it
	for (size_t i = slen; i < len; i++) 
	{
		m_buffer[m_pos + i] = 0;
	}
	m_pos += static_cast<int>(len);
}

inline void PacketWriter::WriteWideString(const std::wstring& str, size_t len) 
{
	size_t slen = str.size();

	if (len < slen) 
	{
		throw std::invalid_argument("WriteString used with a length shorter than string size");
	}

	wcscpy_s((wchar_t*)GetBuffer(m_pos, static_cast<int>(len * 2)), len * 2, str.c_str());

	m_pos += (int)(len * 2);
}


inline void PacketWriter::WriteNoLengthString(const std::string& str) 
{
	WriteString(str, str.size());
}

inline void PacketWriter::WriteString(const std::string& str) 
{
	size_t len = str.size();
	Write<uint16_t>((uint16_t)len);
	WriteString(str, str.size());
}

inline void PacketWriter::WriteZeros(int zeros) 
{

	for (int i = 0; i < zeros; i++)
	{
		Write<byte>(0);
	}
}

template <typename T>
void PacketWriter::Fill(int times) 
{
	for (int i = 0; i < times; i++) {
		Write<T>(times);
	}
}