//Experimental code virtualization - AlSch092 @ Github  (https://github.com/alsch092/simpleCodeVirtualizer/)
#pragma once
#include <stdint.h>
#include <mutex>
#include <unordered_map> //for opcode mappings once we add in randomization
#include <random>
#include <intrin.h>
#include <iostream>

#define USING_OBFUSCATE //comment this out to disable opcode obfuscation

#ifdef USING_OBFUSCATE
#define XOR_KEY 0x12345678
#define OBFUSCATE   ^ XOR_KEY
#define DEOBFUSCATE OBFUSCATE
#endif

#ifdef _M_X64  
#define _UINT uint64_t

extern "C"
{
    _UINT VM_Call(_UINT callAddress, _UINT numParameters, _UINT* parameters); //asm stub for VM_CALL opcode since we can't inline - we pass any parameters as an array 
}

#else
#define _UINT uint32_t
#endif

enum class VM_Opcode : _UINT //these can be randomized at runtime on each instance of the program , we'll implement this soon
{
    VM_PUSH,
    VM_POP,

    VM_ADD, //int
    VM_SUB,
    VM_MUL,
    VM_DIV,

    VM_FL_ADD, //float
    VM_FL_SUB,
    VM_FL_MUL,
    VM_FL_DIV,

    VM_MOVE, //move address to address
    VM_MOV_REGISTER_TO_REGISTER,
    VM_MOV_IMMEDIATE_TO_REGISTER,

    VM_GET_TOP_STACK,

    VM_CALL, //basic __cdecl in x86, x64 only currently works with no parameters in function, but will be fixed soon

    VM_JL,
    VM_JLE,
    VM_JG,
    VM_JGE,
    VM_JE,
    VM_JNE,
    VM_JMP_OFFSET, //directly modify IP, non-conditional jump
    VM_JMP_ABSOLUTE, //jump outside of bytecode? might not be feasible in VS x64 since we need to call an asm stub which jumps, which requires atleast one register modification and thus is not a perfect jmp

    VM_CMP,

    VM_STDOUT,
    VM_DBG_BREAK,

    VM_NOP,
    VM_END_FUNC //each bytecode block must end with this opcode
};

class VirtualMachine
{
public:

    VirtualMachine(int stackSize) : stackSize(stackSize)
    {
        if (stack == nullptr)
            stack = new _UINT[stackSize];
    }

    ~VirtualMachine()
    {
        if (stack != nullptr)
            delete[] stack;
    }

    void SetStackSize(_UINT newSize)
    {
        if (newSize == 0)
        {
            delete[] this->stack;
            this->stack = nullptr;
            this->stackSize = 0;
            return;
        }

        _UINT* newStack = new (std::nothrow) _UINT[newSize];
        if (newStack == nullptr)
        {
            std::cerr << "Memory allocation failed for stack resizing!" << std::endl;
            return;
        }

        if (this->stack != nullptr)
        {
            // Manually compute the smaller of the two sizes
            _UINT copySize = (this->stackSize < newSize) ? this->stackSize : newSize;

            for (_UINT i = 0; i < copySize; i++)
            {
                newStack[i] = this->stack[i];
            }

            delete[] this->stack;
        }

        this->stack = newStack;
        this->stackSize = newSize;
    }

    /*
        bool Execute(_UINT* virtualizedCode, uint32_t executeSize) - executes bytecode
        returns `true` on success, `false` on failure
    */
    template<typename T>
    T Execute(_UINT* bytecode, uint32_t executeSize)
    {
        if (bytecode == nullptr || executeSize == 0)
            return false;

        T retVal = 0;

        ip = (_UINT)&bytecode[0];

        //adding a RAII lock means __try/__except won't compile without errors - it's up to the caller to ensure we don't dereference unallocated memory or execute past the buffer
        std::lock_guard<std::mutex> lock(execution_mtx); //multi threading could potentially lead to sp/ip corruption, so use a mutex

        for (uint32_t i = 0; i < executeSize; i++)
        {
            VM_Opcode vm_opcode = *(VM_Opcode*)ip;
            ip += sizeof(_UINT);

#ifdef USING_OBFUSCATE
            vm_opcode = (VM_Opcode)((_UINT)vm_opcode DEOBFUSCATE);
#endif

            switch (vm_opcode)
            {
            case VM_Opcode::VM_PUSH: //push = write to stack, increment sp
            {
                memcpy((void*)&stack[sp++], (const void*)ip, sizeof(_UINT)); //using memcpy allows us to work with both float and int without losing precision
                ip += sizeof(_UINT);
            }  break;


            case VM_Opcode::VM_POP:
                sp--;
                break;

            case VM_Opcode::VM_ADD: //arithmetic operations (+,-,*,/) pop two values from the stack and place the result in the into stack's sp index
            {
                _UINT b = stack[--sp];
                _UINT a = stack[--sp];
                stack[sp] = a + b;
            } break;

            case VM_Opcode::VM_SUB:
            {
                _UINT b = stack[--sp];
                _UINT a = stack[--sp];
                stack[sp] = a - b;
            } break;

            case VM_Opcode::VM_MUL:
            {
                _UINT b = stack[--sp];
                _UINT a = stack[--sp];
                stack[sp] = a * b;
            } break;

            case VM_Opcode::VM_DIV:
            {
                _UINT b = stack[--sp];
                _UINT a = stack[--sp];
                stack[sp] = a / b;
            } break;

            case VM_Opcode::VM_FL_ADD: //we need to use memcpy for floats to avoid losing precision since our stack is _UINT 
            {
                float b = 0;
                memcpy((void*)&b, (const void*)&stack[--sp], sizeof(float));

                float a = 0;
                memcpy((void*)&a, (const void*)&stack[--sp], sizeof(float));

                float c = a + b;
                memcpy((void*)&stack[sp], &c, sizeof(float));
            }break;

            case VM_Opcode::VM_FL_SUB:
            {
                float b = 0;
                memcpy((void*)&b, (const void*)&stack[--sp], sizeof(float));

                float a = 0;
                memcpy((void*)&a, (const void*)&stack[--sp], sizeof(float));

                float c = a - b;
                memcpy((void*)&stack[sp], &c, sizeof(float));
            }break;

            case VM_Opcode::VM_FL_MUL:
            {
                float b = 0;
                memcpy((void*)&b, (const void*)&stack[--sp], sizeof(float));

                float a = 0;
                memcpy((void*)&a, (const void*)&stack[--sp], sizeof(float));

                float c = a * b;
                memcpy((void*)&stack[sp], &c, sizeof(float));
            }break;

            case VM_Opcode::VM_FL_DIV:
            {
                float b = 0;
                memcpy((void*)&b, (const void*)&stack[--sp], sizeof(float));

                float a = 0;
                memcpy((void*)&a, (const void*)&stack[--sp], sizeof(float));

                if (b == 0)
                {
                    std::cerr << "Division by zero error in bytecode!" << std::endl;
                    return false;
                }

                float c = a / b;
                memcpy((void*)&stack[sp], &c, sizeof(float));
            }break;

            case VM_Opcode::VM_MOV_REGISTER_TO_REGISTER: // ex. mov 0, 1   (move register 1 into register 0, similar to mov ax,bx)
            {
                _UINT lhs_index = *(_UINT*)ip;
                ip += sizeof(_UINT);

                _UINT rhs_index = *(_UINT*)ip;
                ip += sizeof(_UINT);

                if (lhs_index < MAX_REGISTERS && rhs_index < MAX_REGISTERS)
                    registers[lhs_index] = registers[rhs_index];
                else
                    return false; //invalid register index
            } break;

            case VM_Opcode::VM_MOV_IMMEDIATE_TO_REGISTER: //ex. mov ax, 12345678
            {
                _UINT register_index = *(_UINT*)ip; //should be 0 through MAX_REGISTERS-1 (0-indexed)
                ip += sizeof(_UINT);

                _UINT value = *(_UINT*)ip;
                ip += sizeof(_UINT);

                if (register_index < MAX_REGISTERS)
                    registers[register_index] = value;
                else
                    return false; //invalid register index
            } break;

            case VM_Opcode::VM_GET_TOP_STACK: // mov myVar, [sp]
            {
                _UINT varAddress = *(_UINT*)ip;
                ip += sizeof(_UINT);
                memcpy((void*)varAddress, (const void*)&stack[sp], sizeof(_UINT));
                //*(_UINT*)varAddress = stack[sp];
            }break;

            case VM_Opcode::VM_CMP: //how do we best implement this, given that someone could pass in two class objects with overloaded comparison operators?
            {
                _UINT b = stack[--sp];
                _UINT a = stack[--sp];

                if (a == b)
                {
                    cmp_flag = ComparisonFlag::Equal;
                }
                else if (a < b)
                {
                    cmp_flag = ComparisonFlag::Less;
                }
                else
                {
                    cmp_flag = ComparisonFlag::Greater;
                }

            }break;

            case VM_Opcode::VM_JMP_OFFSET:
            {
                int offset = *(int*)ip;
                ip += (sizeof(_UINT) + offset);
            }break;

            case VM_Opcode::VM_CALL: //x86 works okay, however in x64, functions with parameters are not supported yet, this will be added shortly
            {
                _UINT numParameters = *(_UINT*)ip;
                ip += sizeof(_UINT);
                _UINT callAddress = *(_UINT*)ip;

#ifdef _M_X64  
                _UINT* parameters = new _UINT[numParameters];

                for (int i = 0; i < numParameters; i++)
                {
                    memcpy((void*)&parameters[i], (const void*)&(stack[sp - numParameters + i]), sizeof(_UINT));
                }

                retVal = VM_Call(callAddress, numParameters, parameters); //parameters need to correctly go into rcx, rdx, r8, r9, [rsp+...]
                delete[] parameters;
#else
                for (int i = 0; i < numParameters; i++) //x86 cdecl calling convention, push parameters onto stack then call
                {
                    _UINT parameter = stack[sp - numParameters + i];

                    __asm { push parameter }
                }

                __asm
                {
                    call callAddress
                }

                for (int i = 0; i < numParameters; i++)
                {
                    __asm { add esp, 4 }
                }
#endif
            }break;

            case VM_Opcode::VM_STDOUT:
            {
                _UINT textAddress = *(_UINT*)ip;
                ip += sizeof(_UINT);
                std::cout << (const char*)textAddress << std::endl;
            }break;

            case VM_Opcode::VM_NOP: //do nothing
                break;

            case VM_Opcode::VM_END_FUNC: //since many opcodes increment IP, our executeSize won't map directly to the number of UINT's in the bytecode
                i = executeSize;
                break;

            case VM_Opcode::VM_DBG_BREAK:
                __debugbreak();
                break;

            default: //opcode unknown
                break;
            };
        }

        ip = 0;

        for (int i = 0; i < MAX_REGISTERS; i++)
            registers[i] = 0;

        return retVal;
    }

private:
    const static int MAX_REGISTERS = 8; //can be increased if needed

    _UINT registers[MAX_REGISTERS]{ 0 };  //general purpose

    _UINT ip = 0;
    _UINT sp = 0;

    _UINT* stack = nullptr;
    _UINT stackSize = 0;

    std::mutex execution_mtx;

    std::unordered_map<UINT, UINT> opcodeMappings; //for randomizing opcodes, will be implemented soon

    enum ComparisonFlag
    {
        Equal,
        Less,
        Greater,
    };

    ComparisonFlag cmp_flag = Equal;
};