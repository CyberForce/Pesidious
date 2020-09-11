#include <iostream>
#include <fstream>
#include <pe_bliss.h>
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

	std::auto_ptr<pe_base> image;
	PE_TEST_EXCEPTION(image.reset(new pe_base(pe_factory::create_pe(*pe_file))), "Creation, type detection and copying test", test_level_critical);
	
	PE_TEST(!image->has_overlay(), "Overlay test", test_level_normal);
	PE_TEST(image->get_stub_overlay()[1] == 0x1F, "Stub test 1", test_level_normal);
	PE_TEST_EXCEPTION(image->fill_stub_overlay(0x11), "Stub test 2", test_level_normal);
	PE_TEST(image->get_stub_overlay()[1] == 0x11, "Stub test 3", test_level_normal);
	PE_TEST_EXCEPTION(image->strip_stub_overlay(), "Stub test 4", test_level_normal);
	PE_TEST(image->get_stub_overlay().empty(), "Stub test 5", test_level_normal);

	std::cout << "PE Header tests..." << std::endl;

	PE_TEST(!image->directory_exists(pe_win::image_directory_entry_com_descriptor), "Directory test 1", test_level_normal);
	PE_TEST(image->directory_exists(pe_win::image_directory_entry_import), "Directory test 2", test_level_normal);
	PE_TEST(image->has_imports(), "Directory test 3", test_level_normal);
	PE_TEST(!image->has_exports(), "Directory test 4", test_level_normal);

	PE_TEST(image->get_subsystem() == pe_win::image_subsystem_windows_cui, "Subsystem test 1", test_level_normal);
	PE_TEST(image->is_console(), "Subsystem test 2", test_level_normal);
	PE_TEST(!image->is_gui(), "Subsystem test 3", test_level_normal);

	image->set_subsystem(pe_win::image_subsystem_native_windows);
	PE_TEST(image->get_subsystem() == pe_win::image_subsystem_native_windows, "Subsystem test 4", test_level_normal);

	PE_TEST(image->get_pe_signature() == 0x4550, "PE Signature test", test_level_normal);

	PE_TEST(image->get_file_alignment() == 0x200, "File Alignment test 1", test_level_normal);
	PE_TEST_EXPECT_EXCEPTION(image->set_file_alignment(123), pe_exception::incorrect_file_alignment, "File Alignment test 2", test_level_normal);
	PE_TEST_EXCEPTION(image->set_file_alignment(0x1000), "File Alignment test 3", test_level_normal);
	PE_TEST(image->get_file_alignment() == 0x1000, "File Alignment test 4", test_level_normal);

	PE_TEST(image->get_section_alignment() == 0x1000, "Section Alignment test", test_level_normal);

	PE_TEST(image->get_number_of_rvas_and_sizes() == 0x10, "Data directories test", test_level_normal);

	PE_TEST(image->check_characteristics_flag(pe_win::image_file_executable_image), "Image Characteristics test 1", test_level_normal);
	PE_TEST(!image->check_characteristics_flag(pe_win::image_file_dll), "Image Characteristics test 2", test_level_normal);

	PE_TEST(image->get_size_of_headers() == 0x400, "Size of headers test", test_level_normal);

	PE_TEST(image->get_dll_characteristics() == 0x8140, "Image DLL Characteristics test", test_level_normal);

	if(image->get_pe_type() == pe_type_32)
	{
		PE_TEST(image->get_directory_rva(pe_win::image_directory_entry_import) == 0x1C9E4, "Directory RVA test 1", test_level_normal);
		PE_TEST(image->get_directory_size(pe_win::image_directory_entry_import) == 0x3C, "Directory size test 1", test_level_normal);

		PE_TEST(image->get_minor_os_version() == 1 && image->get_major_os_version() == 5, "OS Version test", test_level_normal);
		PE_TEST(image->get_minor_subsystem_version() == 1 && image->get_major_subsystem_version() == 5, "Subsystem Version test", test_level_normal);

		PE_TEST(image->get_pe_header_start() == 0xE0, "e_lfanew test", test_level_normal);

		PE_TEST(image->get_size_of_image() == 0x41000, "Size of Image test", test_level_normal);
		PE_TEST(image->get_ep() == 0x6851, "Entry Point test", test_level_normal);

		PE_TEST(image->get_characteristics() == 0x102, "Image Characteristics test 3", test_level_normal);

		PE_TEST(image->get_size_of_optional_header() == 0xE0, "Size of optional header test", test_level_normal);

		PE_TEST(image->get_magic() == 0x10B, "PE Magic test", test_level_normal);

		PE_TEST(image->get_image_base_32() == 0x400000, "Image Base test 1", test_level_normal);

		{
			uint32_t image_base;
			image->get_image_base(image_base);
			PE_TEST(image_base == 0x400000, "Image Base test 2", test_level_normal);
		}

		PE_TEST(image->get_heap_size_commit_32() == 0x1000, "Heap Size Commit test 1", test_level_normal);
		PE_TEST(image->get_heap_size_reserve_32() == 0x100000, "Heap Size Reserve test 1", test_level_normal);
		PE_TEST(image->get_stack_size_commit_32() == 0x1000, "Stack Size Commit test 1", test_level_normal);
		PE_TEST(image->get_stack_size_reserve_32() == 0x100000, "Stack Size Reserve test 1", test_level_normal);

		{
			uint32_t size;
			image->get_heap_size_commit(size);
			PE_TEST(size == 0x1000, "Heap Size Commit test 2", test_level_normal);
			image->get_heap_size_reserve(size);
			PE_TEST(size == 0x100000, "Heap Size Reserve test 2", test_level_normal);
			image->get_stack_size_commit(size);
			PE_TEST(size == 0x1000, "Stack Size Commit test 2", test_level_normal);
			image->get_stack_size_reserve(size);
			PE_TEST(size == 0x100000, "Stack Size Reserve test 2", test_level_normal);
		}

		PE_TEST(image->get_time_date_stamp() == 0x508E65A3, "TimeStamp test", test_level_normal);
		PE_TEST(image->get_machine() == 0x014C, "Machine test", test_level_normal);
	}
	else
	{
		PE_TEST(image->get_directory_rva(pe_win::image_directory_entry_import) == 0x223EC, "Directory RVA test", test_level_normal);
		PE_TEST(image->get_directory_size(pe_win::image_directory_entry_import) == 0x3C, "Directory size test", test_level_normal);

		PE_TEST(image->get_pe_header_start() == 0xF0, "e_lfanew test", test_level_normal);

		PE_TEST(image->get_minor_os_version() == 2 && image->get_major_os_version() == 5, "OS Version test", test_level_normal);
		PE_TEST(image->get_minor_subsystem_version() == 2 && image->get_major_subsystem_version() == 5, "Subsystem Version test", test_level_normal);

		PE_TEST(image->get_size_of_image() == 0x48000, "Size of Image test", test_level_normal);
		PE_TEST(image->get_ep() == 0x7A64, "Entry Point test", test_level_normal);

		PE_TEST(image->get_characteristics() == 0x22, "Image Characteristics test 3", test_level_normal);

		PE_TEST(image->get_size_of_optional_header() == 0xF0, "Size of optional header test", test_level_normal);

		PE_TEST(image->get_magic() == 0x20B, "PE Magic test", test_level_normal);

		PE_TEST(image->get_image_base_64() == 0x0000000140000000ull, "Image Base test 1", test_level_normal);

		{
			uint64_t image_base;
			image->get_image_base(image_base);
			PE_TEST(image_base == 0x0000000140000000ull, "Image Base test 2", test_level_normal);
		}

		PE_TEST(image->get_heap_size_commit_64() == 0x1000, "Heap Size Commit test 1", test_level_normal);
		PE_TEST(image->get_heap_size_reserve_64() == 0x100000, "Heap Size Reserve test 1", test_level_normal);
		PE_TEST(image->get_stack_size_commit_64() == 0x1000, "Stack Size Commit test 1", test_level_normal);
		PE_TEST(image->get_stack_size_reserve_64() == 0x100000, "Stack Size Reserve test 1", test_level_normal);

		{
			uint64_t size;
			image->get_heap_size_commit(size);
			PE_TEST(size == 0x1000, "Heap Size Commit test 2", test_level_normal);
			image->get_heap_size_reserve(size);
			PE_TEST(size == 0x100000, "Heap Size Reserve test 2", test_level_normal);
			image->get_stack_size_commit(size);
			PE_TEST(size == 0x1000, "Stack Size Commit test 2", test_level_normal);
			image->get_stack_size_reserve(size);
			PE_TEST(size == 0x100000, "Stack Size Reserve test 2", test_level_normal);
		}

		PE_TEST(image->get_time_date_stamp() == 0x508E65B2, "TimeStamp test", test_level_normal);
		PE_TEST(image->get_machine() == 0x8664, "Machine test", test_level_normal);
	}

	image->set_directory_rva(pe_win::image_directory_entry_architecture, 0x1000);
	image->set_directory_size(pe_win::image_directory_entry_architecture, 0x2000);
	PE_TEST(image->get_directory_rva(pe_win::image_directory_entry_architecture) == 0x1000, "Directory RVA test 2", test_level_normal);
	PE_TEST(image->get_directory_size(pe_win::image_directory_entry_architecture) == 0x2000, "Directory size test 2", test_level_normal);

	image->remove_directory(pe_win::image_directory_entry_architecture);
	PE_TEST(image->get_directory_rva(pe_win::image_directory_entry_architecture) == 0, "Directory RVA test 3", test_level_normal);
	PE_TEST(image->get_directory_size(pe_win::image_directory_entry_architecture) == 0, "Directory size test 3", test_level_normal);

	PE_TEST(image->strip_data_directories(0, false) == 0x10 - 3, "Data directories strip test 1", test_level_normal);
	PE_TEST(image->get_number_of_rvas_and_sizes() == 0x10 - 3, "Data directories strip test 2", test_level_normal);
	PE_TEST_EXPECT_EXCEPTION(image->get_directory_rva(pe_win::image_directory_entry_com_descriptor) == 0, pe_exception::directory_does_not_exist, "Directory RVA test 4", test_level_normal);
	PE_TEST_EXPECT_EXCEPTION(image->get_directory_size(pe_win::image_directory_entry_com_descriptor) == 0, pe_exception::directory_does_not_exist, "Directory size test 4", test_level_normal);
	
	if(image->get_pe_type() == pe_type_32)
	{
		PE_TEST(image->strip_data_directories(0, true) == 0x10 - 5, "Data directories strip test 3", test_level_normal);
	}
	else
	{
		PE_TEST(image->strip_data_directories(0, true) == 0x10 - 6, "Data directories strip test 3", test_level_normal);
	}

	std::cout << "Address tests..." << std::endl;

	if(image->get_pe_type() == pe_type_32)
	{
		PE_TEST(image->va_to_rva(image->get_image_base_32() + 1) == 1, "Address conversion test 1", test_level_normal);
		PE_TEST_EXPECT_EXCEPTION(image->va_to_rva(image->get_image_base_32() - 1), pe_exception::incorrect_address_conversion, "Address conversion test 2", test_level_normal);
		PE_TEST(image->rva_to_va_32(1) == image->get_image_base_32() + 1, "Address conversion test 3", test_level_normal);

		{
			uint32_t va;
			image->rva_to_va(1, va);
			PE_TEST(va == image->get_image_base_32() + 1, "Address conversion test 4", test_level_normal);
		}
	}
	else
	{
		PE_TEST(image->va_to_rva(image->get_image_base_64() + 1) == 1, "Address conversion test 1", test_level_normal);
		PE_TEST_EXPECT_EXCEPTION(image->va_to_rva(image->get_image_base_64() - 1), pe_exception::incorrect_address_conversion, "Address conversion test 2", test_level_normal);
		PE_TEST(image->rva_to_va_64(1) == image->get_image_base_64() + 1, "Address conversion test 3", test_level_normal);

		{
			uint64_t va;
			image->rva_to_va(1, va);
			PE_TEST(va == image->get_image_base_64() + 1, "Address conversion test 4", test_level_normal);
		}
	}

	PE_TEST(image->rva_to_file_offset(0x1001) == 0x401, "Address conversion test 5", test_level_normal);
	PE_TEST(image->file_offset_to_rva(0x401) == 0x1001, "Address conversion test 6", test_level_normal);
	PE_TEST(image->file_offset_to_rva(0x1) == 0x1, "Address conversion test 7", test_level_normal);
	PE_TEST(image->rva_to_file_offset(0x1) == 0x1, "Address conversion test 8", test_level_normal);


	std::cout << "Section tests..." << std::endl;
	if(image->get_pe_type() == pe_type_32)
	{
		PE_TEST(image->get_number_of_sections() == 0x6, "Section number test 1", test_level_normal);
	}
	else
	{
		PE_TEST(image->get_number_of_sections() == 0x7, "Section number test 1", test_level_normal);
	}

	PE_TEST(image->get_image_sections().size() == image->get_number_of_sections(), "Section number test 2", test_level_critical);

	PE_TEST(image->get_image_sections().at(0).get_name() == ".text", "Section name test 1", test_level_normal);
	PE_TEST(image->get_image_sections().at(1).get_name() == ".rdata", "Section name test 2", test_level_normal);

	PE_TEST(image->section_from_directory(pe_win::image_directory_entry_import).get_name() == ".rdata", "Section test 1", test_level_normal);
	PE_TEST(image->section_from_rva(0x1000).get_name() == ".text", "Section test 2", test_level_normal);
	PE_TEST(image->section_from_va(image->get_image_base_64() + 0x1000).get_name() == ".text", "Section test 3", test_level_normal);
	PE_TEST(image->section_from_file_offset(0x401).get_name() == ".text", "Section test 4", test_level_normal);
	PE_TEST(image->rva_from_section_offset(image->get_image_sections().at(0), 0x5) == 0x1005, "Section test 5", test_level_normal);

	{
		const section& s = image->get_image_sections().at(0);
		PE_TEST(image->section_data_length_from_rva(s.get_virtual_address() + 123, section_data_raw, false) == s.get_raw_data().size(), "Section test 6", test_level_normal);
		PE_TEST(image->section_data_length_from_rva(s, s.get_virtual_address() + 123, section_data_raw) == s.get_raw_data().size() - 123, "Section test 7", test_level_normal);
		PE_TEST(image->section_data_length_from_rva(s.get_virtual_address() + 123, s.get_virtual_address() + 123, section_data_raw, false) == s.get_raw_data().size() - 123, "Section test 8", test_level_normal);

		PE_TEST_EXPECT_EXCEPTION(image->section_data_length_from_rva(s, s.get_virtual_address() - 1, section_data_raw), pe_exception::rva_not_exists, "Section test 9", test_level_normal);
		PE_TEST_EXPECT_EXCEPTION(image->section_data_length_from_rva(s.get_virtual_address() + 123, s.get_virtual_address() - 1, section_data_raw, false), pe_exception::rva_not_exists, "Section test 10", test_level_normal);

		PE_TEST(image->section_data_length_from_rva(s.get_virtual_address() + 123, section_data_virtual, false) == s.get_aligned_virtual_size(image->get_section_alignment()), "Section test 11", test_level_normal);
		PE_TEST(image->section_data_length_from_rva(s, s.get_virtual_address() + 123, section_data_virtual) == s.get_aligned_virtual_size(image->get_section_alignment()) - 123, "Section test 12", test_level_normal);
		PE_TEST(image->section_data_length_from_rva(s.get_virtual_address() + 123, s.get_virtual_address() + 123, section_data_virtual, false) == s.get_aligned_virtual_size(image->get_section_alignment()) - 123, "Section test 13", test_level_normal);

		PE_TEST_EXPECT_EXCEPTION(image->section_data_length_from_rva(s, s.get_virtual_address() - 1, section_data_virtual), pe_exception::rva_not_exists, "Section test 14", test_level_normal);
		PE_TEST_EXPECT_EXCEPTION(image->section_data_length_from_rva(s.get_virtual_address() + 123, s.get_virtual_address() - 1, section_data_virtual, false), pe_exception::rva_not_exists, "Section test 15", test_level_normal);

		if(image->get_pe_type() == pe_type_32)
		{
			uint32_t base = image->get_image_base_32();
			PE_TEST(image->section_data_length_from_va(base + s.get_virtual_address() + 123, section_data_raw, false) == s.get_raw_data().size(), "Section test 16", test_level_normal);
			PE_TEST(image->section_data_length_from_va(s, base + s.get_virtual_address() + 123, section_data_raw) == s.get_raw_data().size() - 123, "Section test 17", test_level_normal);
			PE_TEST(image->section_data_length_from_va(base + s.get_virtual_address() + 123, base + s.get_virtual_address() + 123, section_data_raw, false) == s.get_raw_data().size() - 123, "Section test 18", test_level_normal);

			PE_TEST_EXPECT_EXCEPTION(image->section_data_length_from_va(s, base + s.get_virtual_address() - 1, section_data_raw), pe_exception::rva_not_exists, "Section test 19", test_level_normal);
			PE_TEST_EXPECT_EXCEPTION(image->section_data_length_from_va(base + s.get_virtual_address() + 123, base + s.get_virtual_address() - 1, section_data_raw, false), pe_exception::rva_not_exists, "Section test 20", test_level_normal);

			PE_TEST(image->section_data_length_from_va(base + s.get_virtual_address() + 123, section_data_virtual, false) == s.get_aligned_virtual_size(image->get_section_alignment()), "Section test 21", test_level_normal);
			PE_TEST(image->section_data_length_from_va(s, base + s.get_virtual_address() + 123, section_data_virtual) == s.get_aligned_virtual_size(image->get_section_alignment()) - 123, "Section test 22", test_level_normal);
			PE_TEST(image->section_data_length_from_va(base + s.get_virtual_address() + 123, base + s.get_virtual_address() + 123, section_data_virtual, false) == s.get_aligned_virtual_size(image->get_section_alignment()) - 123, "Section test 23", test_level_normal);

			PE_TEST_EXPECT_EXCEPTION(image->section_data_length_from_va(s, base + s.get_virtual_address() - 1, section_data_virtual), pe_exception::rva_not_exists, "Section test 24", test_level_normal);
			PE_TEST_EXPECT_EXCEPTION(image->section_data_length_from_va(base + s.get_virtual_address() + 123, base + s.get_virtual_address() - 1, section_data_virtual, false), pe_exception::rva_not_exists, "Section test 25", test_level_normal);

			PE_TEST(image->section_data_from_rva<uint32_t>(0x1005, section_data_raw, false) == 0x505BE900, "Section data test 1", test_level_normal);
			PE_TEST(image->section_data_from_rva<uint32_t>(s, 0x1005, section_data_raw) == 0x505BE900, "Section data test 2", test_level_normal);

			PE_TEST(image->section_data_from_va<uint32_t>(base + 0x1005, section_data_raw, false) == 0x505BE900, "Section data test 3", test_level_normal);
			PE_TEST(image->section_data_from_va<uint32_t>(s, base + 0x1005, section_data_raw) == 0x505BE900, "Section data test 4", test_level_normal);

			PE_TEST(image->section_data_from_rva<uint32_t>(0x1005, section_data_virtual, false) == 0x505BE900, "Section data test 5", test_level_normal);
			PE_TEST(image->section_data_from_rva<uint32_t>(s, 0x1005, section_data_virtual) == 0x505BE900, "Section data test 6", test_level_normal);

			PE_TEST(image->section_data_from_va<uint32_t>(base + 0x1005, section_data_virtual, false) == 0x505BE900, "Section data test 7", test_level_normal);
			PE_TEST(image->section_data_from_va<uint32_t>(s, base + 0x1005, section_data_virtual) == 0x505BE900, "Section data test 8", test_level_normal);

			PE_TEST(image->section_data_from_rva<uint32_t>(0x1, section_data_raw, true) == 0x0300905A, "Section data test 9", test_level_normal);
			PE_TEST(image->section_data_from_va<uint32_t>(base + 0x1, section_data_raw, true) == 0x0300905A, "Section data test 10", test_level_normal);

			PE_TEST(*image->section_data_from_rva(0x1005, section_data_raw, false) == 0x00, "Section data test 11", test_level_normal);
			PE_TEST(*image->section_data_from_rva(s, 0x1005, section_data_raw) == 0x00, "Section data test 12", test_level_normal);
			PE_TEST_EXPECT_EXCEPTION(image->section_data_from_rva(s, 0x999, section_data_raw), pe_exception::rva_not_exists, "Section data test 13", test_level_normal);

			PE_TEST(*image->section_data_from_va(base + 0x1005, section_data_raw, false) == 0x00, "Section data test 14", test_level_normal);
			PE_TEST(*image->section_data_from_va(s, base + 0x1005, section_data_raw) == 0x00, "Section data test 15", test_level_normal);

			PE_TEST(*image->section_data_from_rva(0x1E000 + 0x388C, section_data_virtual, false) == 0x00, "Section data test 16", test_level_normal);
		}
		else
		{
			uint64_t base = image->get_image_base_64();
			PE_TEST(image->section_data_length_from_va(base + s.get_virtual_address() + 123, section_data_raw, false) == s.get_raw_data().size(), "Section test 16", test_level_normal);
			PE_TEST(image->section_data_length_from_va(s, base + s.get_virtual_address() + 123, section_data_raw) == s.get_raw_data().size() - 123, "Section test 17", test_level_normal);
			PE_TEST(image->section_data_length_from_va(base + s.get_virtual_address() + 123, base + s.get_virtual_address() + 123, section_data_raw, false) == s.get_raw_data().size() - 123, "Section test 18", test_level_normal);

			PE_TEST_EXPECT_EXCEPTION(image->section_data_length_from_va(s, base + s.get_virtual_address() - 1, section_data_raw), pe_exception::rva_not_exists, "Section test 19", test_level_normal);
			PE_TEST_EXPECT_EXCEPTION(image->section_data_length_from_va(base + s.get_virtual_address() + 123, base + s.get_virtual_address() - 1, section_data_raw, false), pe_exception::rva_not_exists, "Section test 20", test_level_normal);

			PE_TEST(image->section_data_length_from_va(base + s.get_virtual_address() + 123, section_data_virtual, false) == s.get_aligned_virtual_size(image->get_section_alignment()), "Section test 21", test_level_normal);
			PE_TEST(image->section_data_length_from_va(s, base + s.get_virtual_address() + 123, section_data_virtual) == s.get_aligned_virtual_size(image->get_section_alignment()) - 123, "Section test 22", test_level_normal);
			PE_TEST(image->section_data_length_from_va(base + s.get_virtual_address() + 123, base + s.get_virtual_address() + 123, section_data_virtual, false) == s.get_aligned_virtual_size(image->get_section_alignment()) - 123, "Section test 23", test_level_normal);

			PE_TEST_EXPECT_EXCEPTION(image->section_data_length_from_va(s, base + s.get_virtual_address() - 1, section_data_virtual), pe_exception::rva_not_exists, "Section test 24", test_level_normal);
			PE_TEST_EXPECT_EXCEPTION(image->section_data_length_from_va(base + s.get_virtual_address() + 123, base + s.get_virtual_address() - 1, section_data_virtual, false), pe_exception::rva_not_exists, "Section test 25", test_level_normal);

			PE_TEST(image->section_data_from_rva<uint32_t>(0x1005, section_data_raw, false) == 0x89480001, "Section data test 1", test_level_normal);
			PE_TEST(image->section_data_from_rva<uint32_t>(s, 0x1005, section_data_raw) == 0x89480001, "Section data test 2", test_level_normal);

			PE_TEST(image->section_data_from_va<uint32_t>(base + 0x1005, section_data_raw, false) == 0x89480001, "Section data test 3", test_level_normal);
			PE_TEST(image->section_data_from_va<uint32_t>(s, base + 0x1005, section_data_raw) == 0x89480001, "Section data test 4", test_level_normal);

			PE_TEST(image->section_data_from_rva<uint32_t>(0x1005, section_data_virtual, false) == 0x89480001, "Section data test 5", test_level_normal);
			PE_TEST(image->section_data_from_rva<uint32_t>(s, 0x1005, section_data_virtual) == 0x89480001, "Section data test 6", test_level_normal);

			PE_TEST(image->section_data_from_va<uint32_t>(base + 0x1005, section_data_virtual, false) == 0x89480001, "Section data test 7", test_level_normal);
			PE_TEST(image->section_data_from_va<uint32_t>(s, base + 0x1005, section_data_virtual) == 0x89480001, "Section data test 8", test_level_normal);

			PE_TEST(image->section_data_from_rva<uint32_t>(0x1, section_data_raw, true) == 0x0300905A, "Section data test 9", test_level_normal);
			PE_TEST(image->section_data_from_va<uint32_t>(base + 0x1, section_data_raw, true) == 0x0300905A, "Section data test 10", test_level_normal);

			PE_TEST(*image->section_data_from_rva(0x1005, section_data_raw, false) == 0x01, "Section data test 11", test_level_normal);
			PE_TEST(*image->section_data_from_rva(s, 0x1005, section_data_raw) == 0x01, "Section data test 12", test_level_normal);
			PE_TEST_EXPECT_EXCEPTION(image->section_data_from_rva(s, 0x999, section_data_raw), pe_exception::rva_not_exists, "Section data test 13", test_level_normal);

			PE_TEST(*image->section_data_from_va(base + 0x1005, section_data_raw, false) == 0x01, "Section data test 14", test_level_normal);
			PE_TEST(*image->section_data_from_va(s, base + 0x1005, section_data_raw) == 0x01, "Section data test 15", test_level_normal);

			PE_TEST(*image->section_data_from_rva(0x23000 + 0x46F0, section_data_virtual, false) == 0x00, "Section data test 16", test_level_normal);
		}
	}
	
	PE_TEST(image->section_and_offset_from_rva(0x1005).first == 5, "Section data test 17", test_level_normal);
	PE_TEST(image->section_and_offset_from_rva(0x1005).second->get_name() == ".text", "Section data test 18", test_level_normal);
	
	PE_TEST(image->section_data_length_from_rva(1, section_data_raw, true) == image->get_size_of_headers(), "Section test 26", test_level_normal);
	PE_TEST(image->section_data_length_from_rva(1, 1, section_data_raw, true) == image->get_size_of_headers() - 1, "Section test 27", test_level_normal);

	if(image->get_pe_type() == pe_type_32)
	{
		uint32_t base = image->get_image_base_32();
		PE_TEST(image->section_data_length_from_va(base + 1, section_data_raw, true) == image->get_size_of_headers(), "Section test 28", test_level_normal);
		PE_TEST(image->section_data_length_from_va(base + 1, base + 1, section_data_raw, true) == image->get_size_of_headers() - 1, "Section test 29", test_level_normal);
	}
	else
	{
		uint64_t base = image->get_image_base_64();
		PE_TEST(image->section_data_length_from_va(base + 1, section_data_raw, true) == image->get_size_of_headers(), "Section test 28", test_level_normal);
		PE_TEST(image->section_data_length_from_va(base + 1, base + 1, section_data_raw, true) == image->get_size_of_headers() - 1, "Section test 29", test_level_normal);
	}

	PE_TEST(image->section_attached(image->get_image_sections().at(0)), "Section data test 30", test_level_normal);
	PE_TEST(!image->section_attached(section()), "Section data test 31", test_level_normal);


	{
		const section& s = image->get_image_sections().at(0);
		PE_TEST(s.get_characteristics() == 0x60000020, "Section class test 1", test_level_normal);
		PE_TEST(s.get_name() == ".text", "Section class test 2", test_level_normal);
		PE_TEST(s.get_pointer_to_raw_data() == 0x400, "Section class test 3", test_level_normal);
		PE_TEST(s.get_virtual_address() == 0x1000, "Section class test 4", test_level_normal);

		if(image->get_pe_type() == pe_type_32)
		{
			PE_TEST(s.get_size_of_raw_data() == 0x16E00, "Section class test 5", test_level_normal);
			PE_TEST(s.get_virtual_size() == 0x16C0D, "Section class test 6", test_level_normal);
		}
		else
		{
			PE_TEST(s.get_size_of_raw_data() == 0x19400, "Section class test 5", test_level_normal);
			PE_TEST(s.get_virtual_size() == 0x1923E, "Section class test 6", test_level_normal);
		}
		
		PE_TEST(s.readable(), "Section class test 7", test_level_normal);
		PE_TEST(s.executable(), "Section class test 8", test_level_normal);
		PE_TEST(!s.writeable(), "Section class test 9", test_level_normal);
		PE_TEST(!s.shared(), "Section class test 10", test_level_normal);
		PE_TEST(!s.discardable(), "Section class test 11", test_level_normal);
		PE_TEST(!s.empty(), "Section class test 12", test_level_normal);
	}

	{
		section s;
		PE_TEST_EXPECT_EXCEPTION(image->prepare_section(s), pe_exception::zero_section_sizes, "Prepare Section test 1", test_level_normal);
	}

	{
		section s;
		s.set_raw_data("123");
		PE_TEST_EXCEPTION(image->prepare_section(s), "Prepare Section test 2", test_level_normal);
		PE_TEST(s.get_virtual_size() == pe_utils::align_up(s.get_size_of_raw_data(), image->get_file_alignment()), "Prepare Section test 3", test_level_normal);

		uint16_t old_sections_count = image->get_number_of_sections();
		uint16_t old_size_of_image = image->get_size_of_image();
		PE_TEST_EXCEPTION(image->add_section(s), "Add section test 1", test_level_normal);
		PE_TEST(image->get_number_of_sections() == old_sections_count + 1, "Add section test 2", test_level_normal);
		PE_TEST(image->get_image_sections().back().get_raw_data() == "123", "Add section test 3", test_level_normal);
		PE_TEST(image->get_size_of_image() > old_size_of_image, "Add section test 4", test_level_normal);
	}

	{
		section s;
		s.set_raw_data(std::string("123\0\0\0", 6));
		PE_TEST_EXCEPTION(image->recalculate_section_sizes(s, true), "recalculate_section_sizes test 1", test_level_normal);
		PE_TEST(s.get_raw_data() == "123", "recalculate_section_sizes test 2", test_level_normal);
	}

	PE_TEST_EXPECT_EXCEPTION(image->set_section_virtual_size(image->get_image_sections().at(0), 0x100), pe_exception::error_changing_section_virtual_size, "set_section_virtual_size test 1", test_level_normal);

	{
		section s;
		PE_TEST_EXPECT_EXCEPTION(image->set_section_virtual_size(s, 0), pe_exception::error_changing_section_virtual_size, "set_section_virtual_size test 2", test_level_normal);
	}

	PE_TEST_EXCEPTION(image->set_section_virtual_size(image->get_image_sections().back(), 0x1000), "set_section_virtual_size test 3", test_level_normal);
	PE_TEST(image->get_image_sections().back().get_virtual_size() == 0x1000, "set_section_virtual_size test 4", test_level_normal);

	image->set_file_alignment(0x1000);
	PE_TEST_EXCEPTION(image->realign_all_sections(), "Section realigning test", test_level_normal);
	PE_TEST_EXCEPTION(image->realign_file(0x200), "File realigning test", test_level_normal);

	{
		section& s = image->get_image_sections().back();
		PE_TEST_EXPECT_EXCEPTION(image->expand_section(s, s.get_virtual_address() + 0x5000, 0x1000, pe_base::expand_section_raw), pe_exception::rva_not_exists, "Section expand test 1", test_level_normal);
		PE_TEST(image->expand_section(s, s.get_virtual_address() + 0x100, 0x1000, pe_base::expand_section_raw) == true, "Section expand test 2", test_level_normal);
		PE_TEST(s.get_virtual_size() >= 0x100 + 0x1000, "Section expand test 3", test_level_normal);
		PE_TEST(s.get_size_of_raw_data() >= 0x100 + 0x1000, "Section expand test 4", test_level_normal);

		uint32_t old_raw_size = s.get_size_of_raw_data();
		PE_TEST(image->expand_section(s, s.get_virtual_address() + 0x100, 0x5000, pe_base::expand_section_virtual) == true, "Section expand test 5", test_level_normal);
		PE_TEST(s.get_virtual_size() >= 0x100 + 0x5000, "Section expand test 6", test_level_normal);
		PE_TEST(old_raw_size == s.get_size_of_raw_data(), "Section expand test 7", test_level_normal);
		PE_TEST(image->expand_section(s, s.get_virtual_address() + 0x100, 0x1000, pe_base::expand_section_raw) == false, "Section expand test 8", test_level_normal);
		PE_TEST(image->expand_section(s, s.get_virtual_address() + 0x100, 0x5000, pe_base::expand_section_virtual) == false, "Section expand test 9", test_level_normal);
	}

	{
		image->get_image_sections().pop_back();

		std::stringstream new_pe(std::ios::in | std::ios::out | std::ios::binary);
		PE_TEST_EXCEPTION(rebuild_pe(*image, new_pe, false, true, true), "Rebuild PE test 1", test_level_critical);

		std::auto_ptr<pe_base> new_image;
		PE_TEST_EXCEPTION(new_image.reset(new pe_base(pe_factory::create_pe(new_pe))), "Creation, type detection and copying test 2", test_level_critical);
		
		section_list& sections = image->get_image_sections();
		section_list& new_sections = new_image->get_image_sections();
		PE_TEST(sections.size() == new_sections.size(), "Rebuild PE test 2", test_level_normal);

		for(uint32_t i = 0; i != sections.size(); ++i)
		{
			std::string raw_data_old(sections[i].get_raw_data());
			std::string raw_data_new(new_sections[i].get_raw_data());
			pe_utils::strip_nullbytes(raw_data_old);
			pe_utils::strip_nullbytes(raw_data_new);
			
			std::cout << "Rebuilt PE test iteration " << i << std::endl;
			PE_TEST(raw_data_old == raw_data_new, "Rebuild PE test (section raw data compare)", test_level_normal);
			PE_TEST(sections[i].get_virtual_address() == new_sections[i].get_virtual_address(), "Rebuild PE test (section virtual addresses compare)", test_level_normal);
			PE_TEST(sections[i].get_aligned_virtual_size(image->get_section_alignment()) == new_sections[i].get_aligned_virtual_size(new_image->get_section_alignment()), "Rebuild PE test (section virtual sizes compare)", test_level_normal);
		}


		new_pe.str("");
		PE_TEST_EXCEPTION(rebuild_pe(*image, new_pe, true, true, true), "Rebuild PE test 3", test_level_critical);
		PE_TEST_EXCEPTION(new_image.reset(new pe_base(pe_factory::create_pe(new_pe))), "Creation, type detection and copying test 3", test_level_critical);
		
		image->set_stub_overlay("123");
		new_pe.str("");
		PE_TEST_EXCEPTION(rebuild_pe(*image, new_pe, false, true, true), "Rebuild PE test 4", test_level_critical);
		PE_TEST_EXCEPTION(new_image.reset(new pe_base(pe_factory::create_pe(new_pe))), "Creation, type detection and copying test 4", test_level_critical);
		new_pe.str("");
		PE_TEST_EXCEPTION(rebuild_pe(*image, new_pe, true, true, true), "Rebuild PE test 5", test_level_critical);
		PE_TEST_EXCEPTION(new_image.reset(new pe_base(pe_factory::create_pe(new_pe))), "Creation, type detection and copying test 5", test_level_critical);
	}


	{
		pe_base new_pe(pe_properties_32(), 0x1000, false, pe_win::image_subsystem_windows_cui);
		PE_TEST(new_pe.get_section_alignment() == 0x1000, "Empty PE Creation test 1", test_level_normal);
		PE_TEST(new_pe.get_subsystem() == pe_win::image_subsystem_windows_cui, "Empty PE Creation test 2", test_level_normal);
		PE_TEST(!new_pe.check_characteristics_flag(pe_win::image_file_dll), "Empty PE Creation test 3", test_level_normal);
		
		std::stringstream new_pe_data(std::ios::in | std::ios::out | std::ios::binary);
		PE_TEST_EXCEPTION(rebuild_pe(new_pe, new_pe_data, false, true), "Rebuild PE test 3", test_level_critical);

		std::auto_ptr<pe_base> new_pe_after_rebuild;
		PE_TEST_EXCEPTION(new_pe_after_rebuild.reset(new pe_base(pe_factory::create_pe(new_pe_data))), "Creation, type detection and copying test 4", test_level_critical);
		PE_TEST(new_pe_after_rebuild->get_section_alignment() == 0x1000, "Empty PE Read test 1", test_level_normal);
		PE_TEST(new_pe_after_rebuild->get_number_of_sections() == 0, "Empty PE Read test 2", test_level_normal);
	}

	PE_TEST_END

	return 0;
}
