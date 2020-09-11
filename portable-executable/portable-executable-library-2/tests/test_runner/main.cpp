#include <iostream>
#include <map>
#include <string>
#include <stdio.h>
#include <pe_bliss.h>
#ifndef PE_BLISS_WINDOWS
#include <sys/wait.h>
#endif

#define PE_TEST_32 "../pe_files/image32.exe"
#define PE_TEST_64 "../pe_files/image64.exe"
#define PE_TEST_DOTNET "../pe_files/TestApp.exe"
#define PE_TEST_DEBUG "../pe_files/debug_test.exe"
#define PE_DLL_TEST_32 "../pe_files/test_dll_32.dll"
#define PE_DLL_TEST_64 "../pe_files/test_dll_64.dll"
#define PE_BOUND_IMPORT_TEST_32 "../pe_files/bound32.exe"
#define PE_BOUND_IMPORT_TEST_64 "../pe_files/bound64.exe"
#define PE_TEST_MESSAGE_TABLE "../pe_files/message_table_resource.exe"

class testcase
{
public:
	testcase(const std::string& binary_name, const std::string& testcase_name, const std::vector<std::string>& command_lines = std::vector<std::string>())
		:binary_name_(binary_name), testcase_name_(testcase_name), command_lines_(command_lines)
	{}

	const std::string get_binary_name() const
	{
#ifdef PE_BLISS_WINDOWS
		return binary_name_ + ".exe";
#else
		return binary_name_;
#endif
	}

	const std::string& get_testcase_name() const
	{
		return testcase_name_;
	}

	const std::vector<std::string>& get_command_lines() const
	{
		return command_lines_;
	}

private:
	std::string binary_name_;
	std::string testcase_name_;
	std::vector<std::string> command_lines_;
};

#ifdef PE_BLISS_WINDOWS
#define POPEN _popen
#define PCLOSE _pclose
#define DEV_NULL " 1> nul"
#else
#define POPEN popen
#define PCLOSE pclose
#define DEV_NULL " 1> /dev/null"
#endif

bool run_test(const std::string& path, const std::string& test, bool& warnings_occured, const std::string& cmd = "")
{
	FILE* bin;
#ifdef PE_BLISS_WINDOWS
		bin = POPEN(("\"\"" + path + test + "\" \"" + path + cmd + "\"\" 2>&1" + DEV_NULL).c_str(), "r");
#else
		bin = POPEN(("\"" + path + test + "\" \"" + path + cmd + "\" 2>&1" + DEV_NULL).c_str(), "r");
#endif

	if(bin == NULL)
	{
		std::cerr << "Cannot execute testsuite" << std::endl;
		return false;
	}

	char buf[256];
	while(fgets(buf, sizeof(buf), bin) != NULL)
	{
		warnings_occured = true;
		std::cerr << buf;
	}

#ifdef PE_BLISS_WINDOWS
	return PCLOSE(bin) == 0;
#else
	int stat;
	int wstat = WEXITSTATUS(stat = PCLOSE(bin));
	if(stat < 0 || (wstat != 0 && wstat != 128 + SIGPIPE))
		return false;
	else
		return true;
#endif
}

const std::string get_full_path(const std::string& full_name)
{
	std::string::size_type slash_pos = full_name.find_last_of("/\\");
	if(slash_pos != std::string::npos)
		return full_name.substr(0, slash_pos + 1);
	
	return "";
}

int main(int argc, char* argv[])
{
	bool warnings_occured = false;

	typedef std::vector<testcase> test_list;

	test_list tests;

	{
		std::vector<std::string> command_line;
		command_line.push_back(PE_TEST_32);
		command_line.push_back(PE_TEST_64);
		tests.push_back(testcase("tests_utils", "PE Utils tests"));
		tests.push_back(testcase("tests_basic", "Basic PE tests", command_line));
		tests.push_back(testcase("test_checksum", "PE Checksum tests", command_line));
		tests.push_back(testcase("test_entropy", "PE Entropy tests", command_line));
		tests.push_back(testcase("test_rich_data", "PE Rich Data tests", command_line));
		tests.push_back(testcase("test_imports", "PE Imports tests", command_line));
		tests.push_back(testcase("test_relocations", "PE Relocations tests", command_line));
		tests.push_back(testcase("test_load_config", "PE Load Configuration tests", command_line));
		tests.push_back(testcase("test_exception_directory", "PE Exception Directory tests", command_line));
		tests.push_back(testcase("test_tls", "PE Thread Local Storage tests", command_line));
		tests.push_back(testcase("test_resources", "PE Resource Directory tests", command_line));

		command_line.pop_back();
		//These binaries work with resource classes, which are not dependent on PE format
		//So PE32 is enough to test them
		tests.push_back(testcase("test_resource_viewer", "PE Resource Viewer tests", command_line));
		tests.push_back(testcase("test_resource_manager", "PE Resource Manager tests", command_line));
		tests.push_back(testcase("test_resource_bitmap", "PE Resource Bitmap Read & Write tests", command_line));
		tests.push_back(testcase("test_resource_icon_cursor", "PE Resource Icon/Cursor Read & Write tests", command_line));
		tests.push_back(testcase("test_resource_string_table", "PE Resource String Table Parser tests", command_line));
		tests.push_back(testcase("test_resource_version_info", "PE Resource Version Info & Write tests", command_line));
	}

	{
		std::vector<std::string> message_table_command_line;
		message_table_command_line.push_back(PE_TEST_MESSAGE_TABLE);
		tests.push_back(testcase("test_resource_message_table", "Pe Resource Message Table Parser tests", message_table_command_line));
	}

	{
		std::vector<std::string> dotnet_command_line;
		dotnet_command_line.push_back(PE_TEST_DOTNET);
		tests.push_back(testcase("test_dotnet", "PE Basic .NET tests", dotnet_command_line));
	}

	{
		std::vector<std::string> debug_command_line;
		debug_command_line.push_back(PE_TEST_DEBUG);
		debug_command_line.push_back(PE_TEST_64);
		tests.push_back(testcase("test_debug", "PE Debug Info tests", debug_command_line));
	}

	{
		std::vector<std::string> dll_command_line;
		dll_command_line.push_back(PE_DLL_TEST_32);
		dll_command_line.push_back(PE_DLL_TEST_64);
		tests.push_back(testcase("test_exports", "PE Exports tests", dll_command_line));
	}

	{
		std::vector<std::string> bound_import_command_line;
		bound_import_command_line.push_back(PE_BOUND_IMPORT_TEST_32);
		bound_import_command_line.push_back(PE_BOUND_IMPORT_TEST_64);
		tests.push_back(testcase("test_bound_import", "PE Bound Import tests", bound_import_command_line));
	}

	std::string runner_path(get_full_path(argv[0]));
	
	for(test_list::const_iterator it = tests.begin(); it != tests.end(); ++it)
	{
		const testcase& t = *it;
		bool result = true;
		if(!t.get_command_lines().empty())
		{
			const std::vector<std::string>& cmd_lines = t.get_command_lines();
			for(std::vector<std::string>::const_iterator cmd = cmd_lines.begin(); cmd != cmd_lines.end(); ++cmd)
			{
				std::cout << "Running " << t.get_testcase_name() << " with \"" << (*cmd) << "\"" << std::endl;
				result = run_test(runner_path, t.get_binary_name(), warnings_occured, *cmd);
				if(!result)
					break;
			}
		}
		else
		{
			std::cout << "Running " << t.get_testcase_name() << std::endl;
			result = run_test(runner_path, t.get_binary_name(), warnings_occured);
		}

		if(!result)
		{
			std::cerr << "Some tests hard-failed in this testsuite, exiting..." << std::endl;
			return -1;
		}

		std::cout << std::endl;
	}

	if(warnings_occured)
		std::cout << "Some tests failed, check the log!" << std::endl;
	else
		std::cout << "Everything went just fine!" << std::endl;

	std::cout << "Finished." << std::endl;
	return 0;
}
