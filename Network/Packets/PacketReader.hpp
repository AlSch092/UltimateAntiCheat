#include <iostream>
#include <cstring>

class PacketReader 
{
private:
    const unsigned char* buffer;
    size_t bufferSize;
    size_t position;

public:
    PacketReader(unsigned char* buffer, size_t bufferSize)
        : buffer(buffer), bufferSize(bufferSize), position(0) {}

    bool readBool() 
    {
        return read<char>() != 0;
    }

    int readInt() 
    {
        return read<int>();
    }

    long readLong() 
    {
        return read<long>();
    }

    short readShort() 
    {
        return read<short>();
    }

    std::string readString(size_t length) 
    {
        if (position + length > bufferSize) 
        {
            throw std::runtime_error("Not enough bytes left in buffer to read");
        }

        std::string value(reinterpret_cast<const char*>(&buffer[position]), length);
        position += length;
        return value;
    }

private:
    // Generic read function to read any type from the buffer
    template<typename T>
    T read() 
    {
        static_assert(std::is_trivially_copyable<T>::value, "Type T must be trivially copyable");

        if (position + sizeof(T) > bufferSize) 
        {
            throw std::runtime_error("Not enough bytes left in buffer to read");
        }

        T value;
        std::memcpy(&value, &buffer[position], sizeof(T));
        position += sizeof(T);
        return value;
    }
};
