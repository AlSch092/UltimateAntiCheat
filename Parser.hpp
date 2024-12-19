#pragma once
#include <map>
#include <vector> // for vector
#include <iostream> // for cerr
#include <cstring> // for strcmp

// For printing help message to cout
#define GENERATE_HELP_MESSAGE(cmdName) "\nNAME\n" << cmdName << "\n\nSYNTAX\n" << cmdName << " [[-EnableNetworking] { true | default:false }] [[-EnforceSecureBoot] { true | default:false }] [[-EnforceDSE] { default:true | false }] [[-EnforceNoKDBG] { default:true | false }] [[-UseAntiDebug] { default:true | false }] [[-UseIntegrityCheck] { default:true | false }] [[-CheckThreadIntegrity] { default:true | false }] [[-CheckHypervisor] { default:true | false }] [[-RequireAdmin] { default:true | false } [[-UseDriver] { true | default:true }]\n\n"

/*
	Important definitions for this file:
	argument - any value given by the user
	option - an argument that starts with a "-" and is followed by an argument that is not a flag or another option
	flag - an argument that starts with "-" and is not an option
*/

using namespace std;
/*
	Holds option pairs/arguments
*/
struct CommandLineArgument {
	size_t rawIndex = -1; // the argument's index in rawArgs
	char* argValue = nullptr; // the argument itself
	char* optionValue = nullptr; // the argument following arg; ex. -arg optionValue; nullptr if none
};

/*
	Class to facilitate command line parsing
*/
class Parser {
public:
	Parser(int argc, char** argv);

	char* GetCommandName();
	CommandLineArgument FindArg(char* argStr);
	vector<CommandLineArgument> GetParsedArguments();
	static bool IsOptBool(char* option);
	static bool GetOptAsBool(char* option);
private:
	char** rawArgs; // unparsed arguments
	size_t argSize; // argc
	vector<CommandLineArgument> parsedArgs = {}; // parsed argument/option pairs

	char* GetOptValue(char* argStr);
	bool ArgumentIsAnOption(size_t argIndex);
};