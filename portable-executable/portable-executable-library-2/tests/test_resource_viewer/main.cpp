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

	pe_resource_viewer res(root);

	PE_TEST_EXPECT_EXCEPTION(res.get_resource_count(L"NoName") == 0, pe_exception::resource_directory_entry_not_found, "Resource viewer test 1", test_level_normal);
	PE_TEST(res.get_resource_count(pe_resource_viewer::resource_cursor) == 3, "Resource viewer test 2", test_level_normal);
	
	PE_TEST_EXPECT_EXCEPTION(res.get_language_count(L"NoName", 123) == 0, pe_exception::resource_directory_entry_not_found, "Resource viewer test 3", test_level_normal);
	PE_TEST_EXPECT_EXCEPTION(res.get_language_count(pe_resource_viewer::resource_accelerator, 123), pe_exception::resource_directory_entry_not_found, "Resource viewer test 4", test_level_normal);
	
	PE_TEST_EXPECT_EXCEPTION(res.get_language_count(pe_resource_viewer::resource_cursor, 5) == 0, pe_exception::resource_directory_entry_not_found, "Resource viewer test 5", test_level_normal);
	PE_TEST(res.get_language_count(pe_resource_viewer::resource_cursor, 2) == 1, "Resource viewer test 6", test_level_normal);

	PE_TEST_EXPECT_EXCEPTION(res.get_language_count(pe_resource_viewer::resource_cursor, 5) == 0, pe_exception::resource_directory_entry_not_found, "Resource viewer test 7", test_level_normal);
	PE_TEST(res.get_language_count(pe_resource_viewer::resource_cursor, 2) == 1, "Resource viewer test 8", test_level_normal);
	
	PE_TEST(res.get_language_count(pe_resource_viewer::resource_icon_group, L"MAIN_ICON") == 1, "Resource viewer test 9", test_level_normal);
	PE_TEST_EXPECT_EXCEPTION(res.get_language_count(pe_resource_viewer::resource_icon_group, L"DOESNT_EXIST") == 1, pe_exception::resource_directory_entry_not_found, "Resource viewer test 10", test_level_normal);

	PE_TEST_EXPECT_EXCEPTION(res.get_language_count(L"NONAME", L"DOESNT_EXIST") == 1, pe_exception::resource_directory_entry_not_found, "Resource viewer test 11", test_level_normal);
	PE_TEST_EXPECT_EXCEPTION(res.get_language_count(L"NONAME", 123) == 1, pe_exception::resource_directory_entry_not_found, "Resource viewer test 12", test_level_normal);
	
	PE_TEST(!res.resource_exists(L"NOT_EXISTENT"), "Resource viewer test 13", test_level_normal);
	PE_TEST(res.resource_exists(pe_resource_viewer::resource_bitmap), "Resource viewer test 14", test_level_normal);
	
	PE_TEST(res.list_resource_types().size() == 8, "Resource viewer test 15", test_level_critical);
	PE_TEST(res.list_resource_types()[7] == pe_resource_viewer::resource_manifest, "Resource viewer test 16", test_level_normal);
	
	PE_TEST(res.list_resource_names(pe_resource_viewer::resource_bitmap).size() == 0, "Resource viewer test 17", test_level_critical);
	PE_TEST(res.list_resource_ids(pe_resource_viewer::resource_bitmap).size() == 3, "Resource viewer test 18", test_level_critical);
	
	PE_TEST_EXPECT_EXCEPTION(res.list_resource_names(L"DOESNOT_EXIST"), pe_exception::resource_directory_entry_not_found, "Resource viewer test 19", test_level_normal);
	PE_TEST_EXPECT_EXCEPTION(res.list_resource_ids(L"DOESNOT_EXIST"), pe_exception::resource_directory_entry_not_found, "Resource viewer test 20", test_level_normal);
	
	PE_TEST(res.list_resource_ids(pe_resource_viewer::resource_bitmap).at(2) == 103, "Resource viewer test 21", test_level_normal);
	PE_TEST(res.list_resource_names(pe_resource_viewer::resource_icon_group).size() == 1, "Resource viewer test 22", test_level_critical);
	PE_TEST(res.list_resource_names(pe_resource_viewer::resource_icon_group).at(0) == L"MAIN_ICON", "Resource viewer test 23", test_level_normal);
	
	PE_TEST(res.list_resource_languages(pe_resource_viewer::resource_icon_group, 107).size() == 1, "Resource viewer test 24", test_level_critical);
	PE_TEST(res.list_resource_languages(pe_resource_viewer::resource_icon_group, 107).at(0) == 1049, "Resource viewer test 25", test_level_normal);
	
	PE_TEST(res.list_resource_languages(pe_resource_viewer::resource_icon_group, L"MAIN_ICON").size() == 1, "Resource viewer test 26", test_level_critical);
	PE_TEST(res.list_resource_languages(pe_resource_viewer::resource_icon_group, L"MAIN_ICON").at(0) == 1049, "Resource viewer test 27", test_level_critical);

	PE_TEST_EXPECT_EXCEPTION(res.list_resource_languages(L"UNEXISTENT", L"MAIN_ICON"), pe_exception::resource_directory_entry_not_found, "Resource viewer test 28", test_level_critical);
	PE_TEST_EXPECT_EXCEPTION(res.list_resource_languages(L"UNEXISTENT", 123), pe_exception::resource_directory_entry_not_found, "Resource viewer test 29", test_level_critical);
	
	PE_TEST(res.get_resource_data_by_id(pe_resource_viewer::resource_manifest, 1).get_codepage() == 0x4E4, "Resource viewer test 30", test_level_normal);
	PE_TEST(res.get_resource_data_by_id(pe_resource_viewer::resource_manifest, 1).get_data().substr(0, 15) == "<assembly xmlns", "Resource viewer test 31", test_level_normal);
	PE_TEST_EXPECT_EXCEPTION(res.get_resource_data_by_id(pe_resource_viewer::resource_manifest, 1, 1), pe_exception::resource_data_entry_not_found, "Resource viewer test 32", test_level_normal);
	PE_TEST_EXPECT_EXCEPTION(res.get_resource_data_by_id(L"NONAME", 1), pe_exception::resource_directory_entry_not_found, "Resource viewer test 33", test_level_normal);
	PE_TEST_EXPECT_EXCEPTION(res.get_resource_data_by_id(1049, L"NONAME", 123), pe_exception::resource_directory_entry_not_found, "Resource viewer test 34", test_level_normal);
	PE_TEST(res.get_resource_data_by_id(1033, pe_resource_viewer::resource_manifest, 1).get_codepage() == 0x4E4, "Resource viewer test 35", test_level_normal);

	PE_TEST(res.get_resource_data_by_name(pe_resource_viewer::resource_icon_group, L"MAIN_ICON").get_codepage() == 0x4E4, "Resource viewer test 36", test_level_normal);
	PE_TEST(res.get_resource_data_by_name(pe_resource_viewer::resource_icon_group, L"MAIN_ICON").get_data().substr(0, 5) == std::string("\0\0\1\0\x0d", 5), "Resource viewer test 37", test_level_normal);
	PE_TEST_EXPECT_EXCEPTION(res.get_resource_data_by_name(pe_resource_viewer::resource_icon_group, L"MAIN_ICON", 1), pe_exception::resource_data_entry_not_found, "Resource viewer test 38", test_level_normal);
	PE_TEST_EXPECT_EXCEPTION(res.get_resource_data_by_name(L"NONAME", L"NONAME2"), pe_exception::resource_directory_entry_not_found, "Resource viewer test 39", test_level_normal);
	PE_TEST_EXPECT_EXCEPTION(res.get_resource_data_by_name(1049, L"QWERTY", L"QWERTY"), pe_exception::resource_directory_entry_not_found, "Resource viewer test 40", test_level_normal);
	PE_TEST(res.get_resource_data_by_name(1049, pe_resource_viewer::resource_icon_group, L"MAIN_ICON").get_codepage() == 0x4E4, "Resource viewer test 41", test_level_normal);
	
	PE_TEST_EXPECT_EXCEPTION(res.get_resource_data_by_id(1032, pe_resource_viewer::resource_manifest, 1), pe_exception::resource_directory_entry_not_found, "Resource viewer test 42", test_level_normal);
	PE_TEST_EXPECT_EXCEPTION(res.get_resource_data_by_name(1050, pe_resource_viewer::resource_icon_group, L"MAIN_ICON"), pe_exception::resource_directory_entry_not_found, "Resource viewer test 43", test_level_normal);

	PE_TEST_END

	return 0;
}
