#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#include "test.h"
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

void test_bound_imports(const pe_base& image)
{
	bound_import_module_list imports;
	PE_TEST_EXCEPTION(imports = get_bound_import_module_list(image), "Bound Import Parser test", test_level_critical);
	PE_TEST(imports.size() == 2, "Bound Import test 1", test_level_critical);
	PE_TEST(imports[0].get_module_name() == "USER32.dll"
		&& imports[1].get_module_name() == "KERNEL32.dll", "Bound Import test 2", test_level_normal);

	if(image.get_pe_type() == pe_type_32)
	{
		PE_TEST(imports[0].get_timestamp() == 0x4a5bdb3c
			&& imports[1].get_timestamp() == 0x4afc68c0, "Bound Import test 3", test_level_normal);
	}
	else
	{
		PE_TEST(imports[0].get_timestamp() == 0x4a5bdb3c
			&& imports[1].get_timestamp() == 0, "Bound Import test 3", test_level_normal);
	}

	PE_TEST(imports[0].get_module_ref_count() == 0
		&& imports[1].get_module_ref_count() == 1, "Bound Import test 4", test_level_critical);
	PE_TEST(imports[1].get_module_ref_list()[0].get_module_name() == "NTDLL.DLL"
		&& imports[1].get_module_ref_list()[0].get_timestamp() == 0x4afc681b, "Bound Import test 5", test_level_normal);
}

int main(int argc, char* argv[])
{
	PE_TEST_START
		
	std::auto_ptr<std::ifstream> pe_file;
	if(!open_pe_file(argc, argv, pe_file))
		return -1;

	pe_base image(pe_factory::create_pe(*pe_file));
	test_bound_imports(image);

	{
		std::stringstream new_pe(std::ios::in | std::ios::out | std::ios::binary);
		PE_TEST_EXCEPTION(rebuild_pe(image, new_pe, false, true, true), "Bound Rebuild PE test 1", test_level_critical);
		PE_TEST_EXCEPTION(image = pe_factory::create_pe(new_pe), "Bound Rebuild PE test 2", test_level_critical);
		test_bound_imports(image);
		
		new_pe.str("");
		PE_TEST_EXCEPTION(rebuild_pe(image, new_pe, true, true, true), "Bound Rebuild PE test 3", test_level_critical);
		PE_TEST_EXCEPTION(image = pe_factory::create_pe(new_pe), "Bound Rebuild PE test 4", test_level_critical);
		test_bound_imports(image);
	}

	
	section s;
	s.get_raw_data().resize(1);
	s.set_name("newbound");
	s.readable(true);
	section& new_bound_import_section = image.add_section(s);
	bound_import_module_list imports;
	PE_TEST_EXCEPTION(imports = get_bound_import_module_list(image), "Bound Import Parser test", test_level_critical);
	
	uint32_t old_bound_import_rva = image.get_directory_rva(pe_win::image_directory_entry_bound_import);
	PE_TEST_EXCEPTION(rebuild_bound_imports(image, imports, new_bound_import_section, 0, true, true), "Bound Import Rebuilder test 1", test_level_critical);
	PE_TEST(old_bound_import_rva != image.get_directory_rva(pe_win::image_directory_entry_bound_import), "Bound Import Directory test", test_level_normal);
	test_bound_imports(image);
	
	new_bound_import_section.set_raw_data("111");
	old_bound_import_rva = image.get_directory_rva(pe_win::image_directory_entry_bound_import);
	PE_TEST_EXCEPTION(rebuild_bound_imports(image, imports, new_bound_import_section, 3, true, true), "Bound Import Rebuilder test 2", test_level_critical);
	PE_TEST(new_bound_import_section.get_raw_data().substr(0, 3) == "111", "Bound Import Rebuilder Offset test", test_level_normal);
	PE_TEST(old_bound_import_rva != image.get_directory_rva(pe_win::image_directory_entry_bound_import), "Bound Import Directory test 2", test_level_normal);
	test_bound_imports(image);
	
	PE_TEST_END

	return 0;
}
