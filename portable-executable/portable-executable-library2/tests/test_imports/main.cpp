#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#include "test.h"
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

void compare_imports(const imported_functions_list& imports, const imported_functions_list& new_imports, bool compare_original_iat = true)
{
	PE_TEST(imports.size() == new_imports.size(), "Import compare test (libraries)", test_level_critical);
	for(size_t i = 0; i != imports.size(); ++i)
	{
		std::cout << "Library iteration = " << i << std::endl;
		const import_library::imported_list& funcs = imports[i].get_imported_functions();
		const import_library::imported_list& new_funcs = new_imports[i].get_imported_functions();

		PE_TEST(imports[i].get_name() == new_imports[i].get_name()
			&& imports[i].get_rva_to_iat() == new_imports[i].get_rva_to_iat()
			&& imports[i].get_timestamp() == new_imports[i].get_timestamp(),
			"Import compare test (library properties)", test_level_normal);

		if(compare_original_iat)
		{
			PE_TEST(imports[i].get_rva_to_original_iat() == new_imports[i].get_rva_to_original_iat(), "Import compare test (library properties)", test_level_normal);
		}

		PE_TEST(funcs.size() == new_funcs.size(), "Import compare test (function count)", test_level_critical);
		for(size_t j = 0; j != new_funcs.size(); ++j)
		{
			std::cout << "Function iteration = " << j << std::endl;
			PE_TEST(funcs[i].has_name() == new_funcs[i].has_name(), "Import compare test (function properties)", test_level_normal);

			if(compare_original_iat)
			{
				PE_TEST(funcs[i].get_iat_va() == new_funcs[i].get_iat_va(), "Import compare test (function properties)", test_level_normal);
			}

			if(funcs[i].has_name())
			{
				PE_TEST(funcs[i].get_name() == new_funcs[i].get_name() && funcs[i].get_hint() == new_funcs[i].get_hint(), "Import compare test (function properties)", test_level_normal);
			}
			else
			{
				PE_TEST(funcs[i].get_ordinal() == new_funcs[i].get_ordinal(), "Import compare test (function properties)", test_level_normal);
			}
		}
	}
}

int main(int argc, char* argv[])
{
	PE_TEST_START
		
	std::auto_ptr<std::ifstream> pe_file;
	if(!open_pe_file(argc, argv, pe_file))
		return -1;

	pe_base image(pe_factory::create_pe(*pe_file));

	imported_functions_list imports;
	PE_TEST_EXCEPTION(imports = get_imported_functions(image), "get_imported_functions test", test_level_critical);
	PE_TEST(imports.size() == 2, "Imports test 1", test_level_normal);
	PE_TEST(imports.at(0).get_name() == "USER32.dll", "Imports test 2", test_level_normal);
	PE_TEST(imports.at(1).get_name() == "KERNEL32.dll", "Imports test 3", test_level_normal);

	import_library& user32 = imports.at(0);
	import_library& kernel32 = imports.at(1);

	PE_TEST(user32.get_imported_functions().at(0).has_name() && user32.get_imported_functions().at(0).get_name() == "MessageBoxW", "Imports test 4", test_level_normal);
	PE_TEST(kernel32.get_timestamp() == 0, "Imports test 5", test_level_normal);

	if(image.get_pe_type() == pe_type_32)
	{
		PE_TEST(kernel32.get_rva_to_iat() == 0x00018000, "Imports test 6", test_level_normal);
		PE_TEST(kernel32.get_rva_to_original_iat() == 0x0001CA20, "Imports test 7", test_level_normal);
		PE_TEST(user32.get_imported_functions().at(0).get_hint() == 0x215, "Imports test 8", test_level_normal);
	}
	else
	{
		PE_TEST(kernel32.get_rva_to_iat() == 0x0001B000, "Imports test 6", test_level_normal);
		PE_TEST(kernel32.get_rva_to_original_iat() == 0x00022428, "Imports test 7", test_level_normal);
		PE_TEST(user32.get_imported_functions().at(0).get_hint() == 0x219, "Imports test 8", test_level_normal);
	}
	
	
	imported_functions_list new_imports;

	section s;
	s.get_raw_data().resize(1);
	section& import_section = image.add_section(s);

	import_rebuilder_settings settings(true, false);
	settings.build_original_iat(true);
	settings.enable_auto_strip_last_section(true);
	settings.fill_missing_original_iats(false);
	settings.save_iat_and_original_iat_rvas(true, false);
	settings.set_offset_from_section_start(0);

	image_directory import_dir;
	PE_TEST_EXCEPTION(import_dir = rebuild_imports(image, imports, import_section, settings), "Import rebuilder test 1", test_level_critical);
	PE_TEST_EXCEPTION(new_imports = get_imported_functions(image), "get_imported_functions test 2", test_level_critical);
	PE_TEST(import_dir.get_rva() == image.get_directory_rva(pe_win::image_directory_entry_import)
		&& import_dir.get_size() == image.get_directory_size(pe_win::image_directory_entry_import), "Import directory test 1", test_level_critical);
	PE_TEST(image.get_directory_rva(pe_win::image_directory_entry_iat) && image.get_directory_size(pe_win::image_directory_entry_iat), "Import directory test 2", test_level_critical);

	compare_imports(imports, new_imports);

	settings.zero_directory_entry_iat(true);
	settings.set_offset_from_section_start(1);
	import_section.get_raw_data() = "x";
	PE_TEST_EXCEPTION(import_dir = rebuild_imports(image, imports, import_section, settings), "Import rebuilder test 2", test_level_critical);
	PE_TEST_EXCEPTION(new_imports = get_imported_functions(image), "get_imported_functions test 3", test_level_critical);
	PE_TEST(import_section.get_raw_data().substr(0, 1) == "x", "Import offset test 1", test_level_critical);
	PE_TEST(!image.get_directory_rva(pe_win::image_directory_entry_iat) && !image.get_directory_size(pe_win::image_directory_entry_iat), "Import directory test 3", test_level_critical);
	compare_imports(imports, new_imports);

	settings.set_offset_from_section_start(10);
	import_section.get_raw_data() = "0123456789";
	PE_TEST_EXCEPTION(import_dir = rebuild_imports(image, imports, import_section, settings), "Import rebuilder test 3", test_level_critical);
	PE_TEST_EXCEPTION(new_imports = get_imported_functions(image), "get_imported_functions test 4", test_level_critical);
	PE_TEST(import_section.get_raw_data().substr(0, 10) == "0123456789", "Import offset test 2", test_level_critical);
	compare_imports(imports, new_imports);

	settings.save_iat_and_original_iat_rvas(true, true);
	PE_TEST_EXCEPTION(import_dir = rebuild_imports(image, imports, import_section, settings), "Import rebuilder test 4", test_level_critical);
	PE_TEST_EXCEPTION(new_imports = get_imported_functions(image), "get_imported_functions test 5", test_level_critical);
	compare_imports(imports, new_imports);
	
	settings.build_original_iat(false);
	PE_TEST_EXCEPTION(import_dir = rebuild_imports(image, imports, import_section, settings), "Import rebuilder test 5", test_level_critical);
	PE_TEST_EXCEPTION(new_imports = get_imported_functions(image), "get_imported_functions test 6", test_level_critical);
	PE_TEST(!new_imports[0].get_rva_to_original_iat() && !new_imports[1].get_rva_to_original_iat(), "Import original IAT test", test_level_normal);
	compare_imports(imports, new_imports, false);
	
	settings.build_original_iat(true);
	PE_TEST_EXCEPTION(import_dir = rebuild_imports(image, imports, import_section, settings), "Import rebuilder test 6", test_level_critical);
	PE_TEST_EXCEPTION(new_imports = get_imported_functions(image), "get_imported_functions test 7", test_level_critical);
	PE_TEST(new_imports[0].get_rva_to_original_iat() && new_imports[1].get_rva_to_original_iat(), "Import original IAT test 2", test_level_normal);
	compare_imports(imports, new_imports, false);
	
	settings.fill_missing_original_iats(true);
	settings.build_original_iat(false);
	PE_TEST_EXCEPTION(import_dir = rebuild_imports(image, imports, import_section, settings), "Import rebuilder test 7", test_level_critical);
	PE_TEST_EXCEPTION(new_imports = get_imported_functions(image), "get_imported_functions test 8", test_level_critical);
	compare_imports(imports, new_imports, false);
	
	settings.save_iat_and_original_iat_rvas(false);
	PE_TEST_EXCEPTION(import_dir = rebuild_imports(image, imports, import_section, settings), "Import rebuilder test 8", test_level_critical);
	PE_TEST_EXCEPTION(new_imports = get_imported_functions(image), "get_imported_functions test 9", test_level_critical);
	PE_TEST(imports[0].get_rva_to_iat() != new_imports[0].get_rva_to_iat()
		&& imports[1].get_rva_to_iat() != new_imports[1].get_rva_to_iat(), "IAT rebuilder test", test_level_normal);
	

	import_library lib;
	lib.set_name("TEST.DLL");
	lib.set_timestamp(0x12345);
	imported_function func;
	func.set_name("TestFunc");
	func.set_iat_va(1);
	lib.add_import(func);
	func.set_name("AFunc");
	lib.add_import(func);
	
	func.set_name("");
	func.set_ordinal(123);
	lib.add_import(func);

	func.set_name("BFunc");
	lib.add_import(func);

	imports.push_back(lib);

	import_rebuilder_settings new_settings;
	new_settings.save_iat_and_original_iat_rvas(false);

	PE_TEST_EXCEPTION(import_dir = rebuild_imports(image, imports, import_section, new_settings), "Import rebuilder test 9", test_level_critical);
	PE_TEST_EXCEPTION(new_imports = get_imported_functions(image), "get_imported_functions test 10", test_level_critical);

	PE_TEST(new_imports.size() == 3 && new_imports[2].get_name() == "TEST.DLL", "Added import test", test_level_normal);
	PE_TEST(new_imports[2].get_imported_functions().size() == 4, "Added import function test 1", test_level_normal);
	PE_TEST(new_imports[2].get_imported_functions()[1].get_name() == "AFunc", "Added import function test 2", test_level_normal);
	PE_TEST(new_imports[2].get_imported_functions()[3].get_iat_va() == 1, "Added import function test 3", test_level_normal);
	PE_TEST(new_imports[2].get_imported_functions()[2].has_name() == false, "Added import function test 4", test_level_normal);
	PE_TEST(new_imports[2].get_imported_functions()[2].get_ordinal() == 123, "Added import function test 5", test_level_normal);

	PE_TEST_END

	return 0;
}
