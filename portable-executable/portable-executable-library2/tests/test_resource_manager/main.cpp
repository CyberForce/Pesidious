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

	PE_TEST(res.remove_resource_type(pe_resource_viewer::resource_bitmap) == true, "Resource Manager test 1", test_level_normal);
	PE_TEST(res.remove_resource_type(pe_resource_viewer::resource_bitmap) == false, "Resource Manager test 2", test_level_normal);
	PE_TEST(res.remove_resource(L"DOESNOT_EXIST") == false, "Resource Manager test 3", test_level_normal);
	
	PE_TEST(res.remove_resource(pe_resource_viewer::resource_icon_group, 107) == true, "Resource Manager test 4", test_level_normal);
	PE_TEST(res.remove_resource(pe_resource_viewer::resource_icon_group, 107) == false, "Resource Manager test 5", test_level_normal);
	PE_TEST(res.remove_resource(pe_resource_viewer::resource_icon_group, L"MAIN_ICON") == true, "Resource Manager test 6", test_level_normal);
	PE_TEST(res.remove_resource(pe_resource_viewer::resource_icon_group, L"MAIN_ICON") == false, "Resource Manager test 7", test_level_normal);
	PE_TEST(res.remove_resource(pe_resource_viewer::resource_bitmap, 101) == false, "Resource Manager test 8", test_level_normal);
	PE_TEST(res.remove_resource(pe_resource_viewer::resource_bitmap, L"TEST") == false, "Resource Manager test 9", test_level_normal);
	PE_TEST(res.remove_resource(L"TEST", 1) == false, "Resource Manager test 10", test_level_normal);
	PE_TEST(res.remove_resource(L"TEST", L"TEST") == false, "Resource Manager test 11", test_level_normal);
	
	PE_TEST(res.remove_resource(pe_resource_viewer::resource_cursor_group, 104, 1047) == false, "Resource Manager test 12", test_level_normal);
	PE_TEST(res.remove_resource(pe_resource_viewer::resource_cursor_group, 104, 1049) == true, "Resource Manager test 13", test_level_normal);
	PE_TEST(res.remove_resource(pe_resource_viewer::resource_cursor_group, 104, 1049) == false, "Resource Manager test 14", test_level_normal);
	PE_TEST(res.remove_resource(L"TEST", 100, 1049) == false, "Resource Manager test 15", test_level_normal);
	PE_TEST(res.remove_resource(L"TEST", L"TEST", 1049) == false, "Resource Manager test 16", test_level_normal);
	PE_TEST(res.remove_resource(pe_resource_viewer::resource_cursor_group, L"TEST", 1049) == false, "Resource Manager test 17", test_level_normal);

	PE_TEST_EXCEPTION(res.add_resource("res data", pe_resource_viewer::resource_rcdata, L"TESTNAME", 1049, 123, 12345), "Resource Manager test 18", test_level_normal);
	PE_TEST(res.get_resource_data_by_name(1049, pe_resource_viewer::resource_rcdata, L"TESTNAME").get_data() == "res data", "Resource Manager test 19", test_level_normal);
	PE_TEST(res.get_resource_data_by_name(1049, pe_resource_viewer::resource_rcdata, L"TESTNAME").get_codepage() == 123, "Resource Manager test 20", test_level_normal);

	PE_TEST_EXCEPTION(res.add_resource("res data 2", L"ROOT", L"TESTNAME", 1049, 456, 12345), "Resource Manager test 21", test_level_normal);
	PE_TEST(res.get_resource_data_by_name(1049, L"ROOT", L"TESTNAME").get_data() == "res data 2", "Resource Manager test 22", test_level_normal);
	PE_TEST(res.get_resource_data_by_name(1049, L"ROOT", L"TESTNAME").get_codepage() == 456, "Resource Manager test 23", test_level_normal);

	PE_TEST_EXCEPTION(res.add_resource("res data", pe_resource_viewer::resource_rcdata, 12345, 1049, 123, 12345), "Resource Manager test 24", test_level_normal);
	PE_TEST(res.get_resource_data_by_id(1049, pe_resource_viewer::resource_rcdata, 12345).get_data() == "res data", "Resource Manager test 25", test_level_normal);
	PE_TEST(res.get_resource_data_by_id(1049, pe_resource_viewer::resource_rcdata, 12345).get_codepage() == 123, "Resource Manager test 26", test_level_normal);

	PE_TEST_EXCEPTION(res.add_resource("res data 2", L"ROOT", 12345, 1049, 456, 12345), "Resource Manager test 27", test_level_normal);
	PE_TEST(res.get_resource_data_by_id(1049, L"ROOT", 12345).get_data() == "res data 2", "Resource Manager test 28", test_level_normal);
	PE_TEST(res.get_resource_data_by_id(1049, L"ROOT", 12345).get_codepage() == 456, "Resource Manager test 29", test_level_normal);

	PE_TEST_EXCEPTION(res.add_resource("res data 3", L"ROOT", 12345, 1049, 456, 12345), "Resource Manager test 30", test_level_normal);
	PE_TEST(res.get_resource_data_by_id(1049, L"ROOT", 12345).get_data() == "res data 3", "Resource Manager test 31", test_level_normal);

	PE_TEST_END

	return 0;
}
