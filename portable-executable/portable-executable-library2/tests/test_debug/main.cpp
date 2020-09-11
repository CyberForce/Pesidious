#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#include "test.h"
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

void debug_test(const debug_info& dbg)
{
	PE_TEST(dbg.get_characteristics() == 0
		&& dbg.get_time_stamp() == 0x50757757
		&& dbg.get_major_version() == 0
		&& dbg.get_minor_version() == 0
		&& dbg.get_rva_of_raw_data() == 0,
		"Debug Basic Info test", test_level_normal);
}

int main(int argc, char* argv[])
{
	PE_TEST_START
		
	std::auto_ptr<std::ifstream> pe_file;
	if(!open_pe_file(argc, argv, pe_file))
		return -1;

	pe_base image(pe_factory::create_pe(*pe_file));
	
	debug_info_list info;
	PE_TEST_EXCEPTION(info = get_debug_information(image), "Debug Info Parser test", test_level_critical);

	if(image.get_pe_type() == pe_type_32)
	{
		{
			PE_TEST(info.size() == 3, "Debug Info test 1", test_level_critical);
			debug_info& dbg = info[0];
			debug_test(dbg);
			PE_TEST(dbg.get_size_of_data() == 0x00008CB1, "Debug Info test 2", test_level_normal);

			PE_TEST(dbg.get_type() == debug_info::debug_type_coff
				&& dbg.get_advanced_info_type() == debug_info::advanced_info_coff, "Debug Info test 3", test_level_critical);

			coff_debug_info advanced;
			PE_TEST_EXCEPTION(advanced = dbg.get_advanced_debug_info<coff_debug_info>(), "Debug COFF Info Parser test", test_level_critical);
			PE_TEST(advanced.get_number_of_line_numbers() == 0
				&& advanced.get_number_of_symbols() == 0x4E9, "Debug Info test 4", test_level_critical);
			PE_TEST(advanced.get_lva_to_first_line_number() == 0
				&& advanced.get_lva_to_first_symbol() == 0x20
				&& advanced.get_rva_to_first_byte_of_code() == 0x1000
				&& advanced.get_rva_to_first_byte_of_data() == 0xE000
				&& advanced.get_rva_to_last_byte_of_code() == 0xE000
				&& advanced.get_rva_to_last_byte_of_data() == 0x7000, "Debug Info test 5", test_level_normal);

			const coff_debug_info::coff_symbol& sym = advanced.get_symbols()[1];
			PE_TEST(sym.get_index() == 0x55 && sym.get_rva() == 0xCD1C
				&& sym.get_section_number() == 1
				&& sym.get_storage_class() == 3
				&& sym.get_type() == 0
				&& !sym.is_file()
				&& sym.get_symbol() == "UnwindUpVec", "Debug Info test 6", test_level_normal);
		}

		{
			debug_info& dbg = info[1];
			debug_test(dbg);
			PE_TEST(dbg.get_size_of_data() == 0x110, "Debug Info test 7", test_level_normal);

			PE_TEST(dbg.get_type() == debug_info::debug_type_misc
				&& dbg.get_advanced_info_type() == debug_info::advanced_info_misc, "Debug Info test 8", test_level_critical);

			misc_debug_info advanced;
			PE_TEST_EXCEPTION(advanced = dbg.get_advanced_debug_info<misc_debug_info>(), "Debug MISC Info Parser test", test_level_critical);
			PE_TEST(advanced.is_exe_name(), "Debug MISC test 1", test_level_normal);
			PE_TEST(!advanced.is_unicode(), "Debug MISC test 2", test_level_normal);
			PE_TEST(advanced.get_data_ansi() == "Debug/debugtest.exe", "Debug MISC test 3", test_level_normal);
		}

		{
			debug_info& dbg = info[2];
			debug_test(dbg);
			PE_TEST(dbg.get_size_of_data() == 0x68, "Debug Info test 9", test_level_normal);

			PE_TEST(dbg.get_type() == debug_info::debug_type_codeview
				&& dbg.get_advanced_info_type() == debug_info::advanced_info_pdb_2_0, "Debug Info test 10", test_level_critical);

			pdb_2_0_info advanced;
			PE_TEST_EXCEPTION(advanced = dbg.get_advanced_debug_info<pdb_2_0_info>(), "Debug PDB 2.0 Info Parser test", test_level_critical);
			PE_TEST(advanced.get_age() == 1, "Debug PDB 2.0 test 1", test_level_normal);
			PE_TEST(advanced.get_signature() == 0x50757757, "Debug PDB 2.0 test 2", test_level_normal);
			PE_TEST(advanced.get_pdb_file_name() == "C:\\Program Files (x86)\\Microsoft Visual Studio\\MyProjects\\debugtest\\Debug\\debugtest.pdb", "Debug PDB 2.0 test 3", test_level_normal);
		}
	}
	else
	{
		PE_TEST(info.size() == 1, "Debug Info test 1", test_level_critical);
		debug_info& dbg = info[0];
		PE_TEST(dbg.get_characteristics() == 0
			&& dbg.get_time_stamp() == 0x50937d36
			&& dbg.get_major_version() == 0
			&& dbg.get_minor_version() == 0
			&& dbg.get_rva_of_raw_data() == 0x0001F300
			&& dbg.get_size_of_data() == 0x0000006F,
			"Debug Basic Info test", test_level_normal);

		PE_TEST(dbg.get_type() == debug_info::debug_type_codeview
			&& dbg.get_advanced_info_type() == debug_info::advanced_info_pdb_7_0, "Debug Info test 2", test_level_critical);

		pdb_7_0_info advanced;
		PE_TEST_EXCEPTION(advanced = dbg.get_advanced_debug_info<pdb_7_0_info>(), "Debug PDB 7.0 Info Parser test", test_level_critical);
		PE_TEST(advanced.get_age() == 1, "Debug PDB 7.0 test 1", test_level_normal);

		pe_win::guid testguid = {0xCC311030, 0xD245, 0x4FF7, {0x9F, 0x16, 0xB5, 0x6D, 0x8B, 0x11, 0x1F, 0x1A}};
		PE_TEST(advanced.get_guid() == testguid, "Debug PDB 7.0 test 2", test_level_normal);
		PE_TEST(advanced.get_pdb_file_name() == "C:\\Users\\Bliss\\Documents\\Visual Studio 2010\\Projects\\hello_world\\x64\\Release\\test1.pdb", "Debug PDB 7.0 test 3", test_level_normal);
	}

	PE_TEST_END

	return 0;
}
