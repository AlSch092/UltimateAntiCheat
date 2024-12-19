#include "Parser.hpp"

Parser::Parser(int argc, char** argv) {
	rawArgs = argv;
	argSize = argc;

	// Fill parsedArgs
	for (int i = 1; i < argSize; ++i) {
		CommandLineArgument parsedArg;
		char* thisArg = rawArgs[i];
		parsedArg.argValue = thisArg;
		parsedArg.rawIndex = i;

		if (ArgumentIsAnOption(i)) {
			parsedArg.optionValue = rawArgs[i + 1];
			i++;
		}

		parsedArgs.push_back(parsedArg);
	}
}

/*
	GetCommandName - basically returns argv[0]
*/
char* Parser::GetCommandName() {
	return rawArgs[0];
}

/*
	FindArg - returns CommandLineArgument of parsedArgs that has an argValue that equals argStr; returns default CommandLineArgument (rawIndex is -1) if not found
*/
CommandLineArgument Parser::FindArg(char* argStr) {
	CommandLineArgument arg;
	for (int i = 0; i < parsedArgs.size(); ++i) {
		arg = parsedArgs[i];
		if (strcmp(arg.argValue, argStr) == 0) {
			return arg;
		}
	}
	return arg;
}

/*
	GetParsedArguments - returns parsedArgs, a vector of all parsed arguments/option pairs
*/
vector<CommandLineArgument> Parser::GetParsedArguments() {
	return parsedArgs;
}

/*
	GetOptValue - returns the optionValue of the argument with the given argStr; returns nullptr if the argument doesn't exist or if the argument isn't an option
*/
char* Parser::GetOptValue(char* argStr) {
	CommandLineArgument arg = FindArg(argStr);
	if (arg.rawIndex == -1) {
		return nullptr;
	}

	for (int i = 0; i < parsedArgs.size(); ++i) {
		CommandLineArgument arg = parsedArgs[i];
		if (strcmp(arg.argValue, argStr) == 0) {
			return arg.optionValue;
		}
	}
	return nullptr;
}

/*
	IsOptBool - returns true if option is a valid variation of true or false; returns false if the option is anything else
*/
bool Parser::IsOptBool(char* option) {
	return ((strcmp(option, "true") == 0) ||
		(strcmp(option, "True") == 0) ||
		(strcmp(option, "TRUE") == 0) ||
		(strcmp(option, "false") == 0) ||
		(strcmp(option, "False") == 0) ||
		(strcmp(option, "FALSE") == 0));
}

bool Parser::GetOptAsBool(char* option) {
	if (option == nullptr) {
		throw "[void]";
	}

	if ((strcmp(option, "true") == 0) ||
		(strcmp(option, "True") == 0) ||
		(strcmp(option, "TRUE") == 0) ) {
		return true;
	}

	if ((strcmp(option, "false") == 0) ||
		(strcmp(option, "False") == 0) ||
		(strcmp(option, "FALSE") == 0) ) {
		return false;
	}
	throw (option);
}

/*
	ArgumentIsAnOption - returns if the argument at position argIndex is an option
*/
bool Parser::ArgumentIsAnOption(size_t argIndex) {
	if (argIndex + 1 >= argSize) { // This means no argument follows this one
		return false;
	}

	char* thisArg = rawArgs[argIndex];
	char* nextArg = rawArgs[argIndex + 1];

	return ((thisArg[0] == '-') && (nextArg[0] != '-'));
}
