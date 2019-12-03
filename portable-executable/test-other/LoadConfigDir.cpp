#include <iostream>
#include <fstream>
#include "../portable-executable-library2/pe_lib/pe_bliss.h"
//#ifdef PE_BLISS_WINDOWS
#include "../portable-executable-library2/samples/lib.h"
//#endif

using namespace pe_bliss;

// Example showing how to rebuild the Load Config directory on a PE file
int main (int argc, char * argv [])
{
	if (argc != 2)
	{
		std :: cout << "Usage: image_config_editor.exe PE_FILE" << std :: endl;
		return 0;
	}

	// Open the file
	std :: ifstream pe_file (argv [1], std :: ios :: in | std :: ios :: binary);
	if (! pe_file)
	{
		std :: cout << "Cannot open" << argv [1] << std :: endl;
		return -1;
	}

	try
	{
		// Create an instance of a PE or PE + class using the factory
		pe_base image (pe_factory :: create_pe (pe_file));

		// Get information about the Load Config directory
		image_config_info info (get_image_config (image));

		// But re-compile this directory, placing it in a new section
		section load_config;
		load_config.get_raw_data (). resize (1); // We cannot add empty sections, so let it have an initial data size of 1
		load_config.set_name ("load_cfg"); // section name
		load_config.readable (true) .writeable (true); // Available for reading and writing
		section & attached_section = image.add_section (load_config); // Add a section and get a link to the added section with calculated sizes

		// If the file had a table of SE Handlers
		if (info.get_se_handler_table_va ())
			info.add_se_handler_rva (0x7777); // Add a new SE Handler to the table (just for the test)

		// If the file did not have a table of Lock prefixes, add it
		// (also for test)
		if (! info.get_lock_prefix_table_va ())
			info.add_lock_prefix_rva (0x9999);

		// Rebuild the Image Load Config directory, rebuild the Lock-prefix table, if any, as well
		// table of SE Handlers, if any
		rebuild_image_config (image, info, attached_section, 1);

		// Create a new PE file
		std :: string base_file_name (argv [1]);
		std :: string :: size_type slash_pos;
		if ((slash_pos = base_file_name.find_last_of ("/ \\")) != std :: string :: npos)
			base_file_name = base_file_name.substr (slash_pos + 1);

		base_file_name = "modified.exe";
		std :: ofstream new_pe_file (base_file_name.c_str (), std :: ios :: out | std :: ios :: binary | std :: ios :: trunc);
		if (! new_pe_file)
		{
			std :: cout << "Cannot create" << base_file_name << std :: endl;
			return -1;
		}

		// Rebuild the PE file
		rebuild_pe (image, new_pe_file);

		std :: cout << "PE was rebuilt and saved to" << base_file_name << std :: endl;
	}
	catch (const pe_exception & e)
	{
		// If an error occurs
		std :: cout << "Error:" << e.what () << std :: endl;
		return -1;
	}

	return 0;
}
