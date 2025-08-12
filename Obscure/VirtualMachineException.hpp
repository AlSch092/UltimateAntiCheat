#pragma once
#include <exception>
#include <unordered_map>
#include <string>

/**
 * @brief Exception class for the Virtual Machine
 *
 * This class inherits from std::exception and provides specific error messages for various VM exceptions.
 * It is used to handle errors that occur during the execution of the virtual machine's bytecode.
 */
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

    /**
     * @brief Overridden method from std::exception, required for inheritance
     *
	 * @return a const char* pointer to the exception message
    */
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