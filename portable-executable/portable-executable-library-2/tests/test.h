#pragma once
#include <string>
#include <iostream>
#include <typeinfo>
#include <exception>
#include <stdlib.h>

enum test_level
{
	test_level_normal,
	test_level_critical
};

static void pe_test_print_error(const std::string& test_name,
	test_level level,
	const std::string& expression,
	const std::string& file, size_t line)
{
	std::cerr << test_name << " - FAIL!" << std::endl
		<< "File: " << file << ", line: " << line << std::endl
		<< "Expression: " << expression << std::endl << std::endl;

	if(level == test_level_critical)
		exit(EXIT_FAILURE);
}

static void pe_test(bool result,
	const std::string& test_name, test_level level,
	const std::string& expression,
	const std::string& file, size_t line)
{
	if(result)
		std::cout << test_name << " - OK" << std::endl;
	else
		pe_test_print_error(test_name, level, expression, file, line);
}

static void pe_test_error(const std::exception& e,
	const std::string& test_name, test_level level,
	const std::string& expression,
	const std::string& file, size_t line)
{
	std::cerr << test_name << " FAIL!" << std::endl
		<< "File: " << file << ", line: " << line << std::endl
		<< "Expression: " << expression << std::endl
		<< "Exception occured: " << e.what() << std::endl
		<< "Exception type: " << typeid(e).name() << std::endl << std::endl;

	if(level == test_level_critical)
		exit(EXIT_FAILURE);
}

#define PE_TEST_TO_STRING(expression) #expression

//Checks the result of expression (true)
#define PE_TEST(expression, test_name, level) \
	try \
	{ \
		pe_test((expression), test_name, level, PE_TEST_TO_STRING(expression), __FILE__, __LINE__); \
	} \
	catch(const std::exception& e) \
	{ \
		pe_test_error(e, test_name, level, PE_TEST_TO_STRING(expression), __FILE__, __LINE__); \
	}

//Runs expression and checks for exceptions
#define PE_TEST_EXCEPTION(expression, test_name, level) \
	try \
	{ \
		(expression); \
		std::cout << test_name << " - OK" << std::endl; \
	} \
	catch(const std::exception& e) \
	{ \
		pe_test_error(e, test_name, level, PE_TEST_TO_STRING(expression), __FILE__, __LINE__); \
	}

//Awaits exception from expression
#define PE_TEST_EXPECT_EXCEPTION(expression, pe_exception_code, test_name, level) \
	try \
	{ \
		(expression); \
		std::cerr << "Expected exception: " << PE_TEST_TO_STRING(pe_exception_code) << std::endl; \
		pe_test_print_error(test_name, level, PE_TEST_TO_STRING(expression), __FILE__, __LINE__); \
	} \
	catch(const pe_exception& e) \
	{ \
		if(e.get_id() == pe_exception_code) \
			std::cout << test_name << " - OK" << std::endl; \
		else \
			pe_test_error(e, test_name, level, PE_TEST_TO_STRING(expression), __FILE__, __LINE__); \
	}


#ifndef PE_FILES_UNUSED
static bool open_pe_file(int argc, char* argv[], std::auto_ptr<std::ifstream>& pe_file)
{
	if(argc != 2)
	{
		std::cerr << "Usage: test.exe PE_FILE" << std::endl;
		return false;
	}
	
	pe_file.reset(new std::ifstream(argv[1], std::ios::in | std::ios::binary));
	if(!*pe_file)
	{
		std::cerr << "Cannot open " << argv[1] << std::endl;
		return false;
	}

	return true;
}
#endif

#define PE_TEST_START \
	try \
	{


#define PE_TEST_END } \
	catch(const std::exception& e) \
	{ \
		pe_test_error(e, "Global Test", test_level_critical, "global test exception handler", __FILE__, __LINE__); \
	}
