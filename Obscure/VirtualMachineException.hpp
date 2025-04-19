#pragma once
#include <exception>
#include <unordered_map>
#include <string>

// VMException class
class VirtualMachineException : public std::exception
{
public:

    enum VMException
    {
        DivisionByZero,
        FragmentedFunction,
        StackOutOfSpace,
        UnknownOpcode,
    };

    VMException type;

    VirtualMachineException(VMException exception) : type(exception)
    {

    }

    const char* what() const noexcept override
    {
        return exceptionMessages.at(type).c_str();
    }

private:

    std::unordered_map<VMException, std::string> exceptionMessages =
    {
        { DivisionByZero, "Division by zero error in bytecode arithmetic" },
        { FragmentedFunction, "Fragmented function error, no end opcode in bytecode" },
        { StackOutOfSpace, "Stack out of space error" },
        { UnknownOpcode, "Unknown opcode in VM bytecode" },
    };
};