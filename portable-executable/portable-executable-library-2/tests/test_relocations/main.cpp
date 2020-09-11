#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#include "test.h"
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

void test_relocations(const pe_base& image, const relocation_table_list& tables, bool read_absolute_entries)
{
	if(image.get_pe_type() == pe_type_32)
	{
		PE_TEST(tables.size() == 30, "Relocation test 1", test_level_critical);
		PE_TEST(tables[1].get_rva() == 0x2000, "Relocation test 2", test_level_normal);
		PE_TEST(tables[1].get_relocations().size() == (read_absolute_entries ? 22 : 21), "Relocation test 3", test_level_critical);
		PE_TEST(tables[1].get_relocations()[1].get_rva() == 0x54, "Relocation test 4", test_level_normal);
		PE_TEST(tables[1].get_relocations()[1].get_type() == pe_win::image_rel_based_highlow, "Relocation test 5", test_level_normal);
	}
	else
	{
		PE_TEST(tables.size() == 7, "Relocation test 1", test_level_critical);
		PE_TEST(tables[1].get_rva() == 0x1C000, "Relocation test 2", test_level_normal);
		PE_TEST(tables[4].get_relocations().size() == (read_absolute_entries ? 6 : 5), "Relocation test 3", test_level_critical);
		PE_TEST(tables[1].get_relocations()[1].get_rva() == 0x4E8, "Relocation test 4", test_level_normal);
		PE_TEST(tables[1].get_relocations()[1].get_type() == pe_win::image_rel_based_dir64, "Relocation test 5", test_level_normal);
	}
}

int main(int argc, char* argv[])
{
	PE_TEST_START

	std::auto_ptr<std::ifstream> pe_file;
	if(!open_pe_file(argc, argv, pe_file))
		return -1;

	pe_base image(pe_factory::create_pe(*pe_file));

	relocation_table_list tables;
	PE_TEST_EXCEPTION(tables = get_relocations(image, true), "Relocation parser test 1", test_level_critical);
	test_relocations(image, tables, true);
	
	tables.clear();
	PE_TEST_EXCEPTION(tables = get_relocations(image, false), "Relocation parser test 2", test_level_critical);
	test_relocations(image, tables, false);

	section& reloc_section = image.section_from_directory(pe_win::image_directory_entry_basereloc);
	PE_TEST_EXCEPTION(rebuild_relocations(image, tables, reloc_section, 0, true, true), "Relocation Rebuilder test 1", test_level_critical);
	PE_TEST_EXCEPTION(tables = get_relocations(image, true), "Relocation parser test 3", test_level_critical);
	test_relocations(image, tables, true);

	PE_TEST_EXCEPTION(rebuild_relocations(image, tables, reloc_section, 0, true, true), "Relocation Rebuilder test 2", test_level_critical);
	PE_TEST_EXCEPTION(tables = get_relocations(image, true), "Relocation parser test 4", test_level_critical);
	test_relocations(image, tables, true);

	section s;
	s.get_raw_data().resize(1);
	s.set_name("newreloc");
	section& new_reloc_section = image.add_section(s);

	uint32_t old_reloc_rva = image.get_directory_rva(pe_win::image_directory_entry_basereloc);

	PE_TEST_EXCEPTION(rebuild_relocations(image, tables, new_reloc_section, 0, true, true), "Relocation Rebuilder test 3", test_level_critical);
	PE_TEST(old_reloc_rva != image.get_directory_rva(pe_win::image_directory_entry_basereloc), "Relocation Rebuilder test 4", test_level_normal);
	
	old_reloc_rva = image.get_directory_rva(pe_win::image_directory_entry_basereloc);

	PE_TEST_EXCEPTION(tables = get_relocations(image, false), "Relocation parser test 5", test_level_critical);
	test_relocations(image, tables, false);
	
	new_reloc_section.set_raw_data("111");
	PE_TEST_EXCEPTION(rebuild_relocations(image, tables, new_reloc_section, 3, true, true), "Relocation Rebuilder test 4", test_level_critical);
	PE_TEST(new_reloc_section.get_raw_data().substr(0, 3) == "111", "Relocation Rebuilder offset test", test_level_normal);
	PE_TEST(old_reloc_rva != image.get_directory_rva(pe_win::image_directory_entry_basereloc), "Relocation Rebuilder test 5", test_level_normal);
	
	PE_TEST_EXCEPTION(tables = get_relocations(image, false), "Relocation parser test 6", test_level_critical);
	test_relocations(image, tables, false);

	relocation_table_list full_tables; //With absolute entries
	PE_TEST_EXCEPTION(full_tables = get_relocations(image, true), "Relocation parser test 7", test_level_critical);
	test_relocations(image, full_tables, true);
	
	pe_base old_image(image);

	PE_TEST_EXCEPTION(rebase_image(image, tables, image.get_image_base_64() + 0x10000), "PE Rebaser test 1", test_level_critical);
	PE_TEST_EXCEPTION(rebase_image(image, full_tables, image.get_image_base_64() - 0x10000), "PE Rebaser test 2", test_level_critical); //Check that rebaser skips absolute entries

	uint16_t section_count = image.get_number_of_sections();
	for(uint16_t i = 0; i != section_count; ++i)
	{
		std::cout << "Rebaser control test iteration: " << i << std::endl;
		PE_TEST(image.get_image_sections().at(i).get_raw_data() == old_image.get_image_sections().at(i).get_raw_data(), "Rebaser control test", test_level_normal);
	}

	PE_TEST_END

	return 0;
}
