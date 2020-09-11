#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#include <pe_bliss_resources.h>
#include "test.h"
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

int main(int argc, char* argv[])
{
	PE_TEST_START
		
	std::auto_ptr<std::ifstream> pe_file;
	if(!open_pe_file(argc, argv, pe_file))
		return -1;

	pe_base image(pe_factory::create_pe(*pe_file));
	
	resource_directory root(get_resources(image));
	
	pe_resource_manager res(root);
	resource_string_table_reader str(res);

	resource_string_list strings;
	PE_TEST_EXCEPTION(strings = str.get_string_table_by_id_lang(1049, 7), "String List Parser test 1", test_level_critical);
	PE_TEST(strings.size() == 4, "String List Parser test 2", test_level_critical);
	PE_TEST(strings.find(111) != strings.end(), "String List Parser test 3", test_level_critical);
	PE_TEST(strings[111] == L"Test String 4", "String List Parser test 4", test_level_normal);

	std::wstring str_111;
	PE_TEST_EXCEPTION(str_111 = str.get_string_by_id(111), "String List Parser test 5", test_level_normal);
	PE_TEST(str_111 == L"Test String 4", "String List Parser test 6", test_level_normal);
	PE_TEST(str_111 == str.get_string_by_id_lang(1049, 111), "String List Parser test 7", test_level_normal);

	PE_TEST_END

	return 0;
}
