#include <iostream>
#include <fstream>
#include "../portable-executable-library2/pe_lib/pe_bliss.h"
//#ifdef PE_BLISS_WINDOWS
#include "../portable-executable-library2/samples/lib.h"
//#endif

using namespace pe_bliss;

// Example showing how to edit TLS (Thread Local Storage) on PE files
int main (int argc, char * argv [])
{
	if (argc != 2)
	{
		std :: cout << "Usage: tls_editor.exe PE_FILE" << std :: endl;
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

		// Get information about the TLS PE file
		// If there is no TLS, this call will throw an exception
		tls_info info (get_tls_info (image));

		// Rebuild TLS
		// It will probably be larger than before our editing,
		// so we write it in a new section so that everything fits
		// (we cannot extend existing sections unless the section is at the very end of the file)
		section new_tls;
		new_tls.get_raw_data (). resize (1); // We cannot add empty sections, so let it have an initial data size of 1
		new_tls.set_name ("new_tls"); // section name
		new_tls.readable (true); // Readable
		section & attached_section = image.add_section (new_tls); // Add a section and get a link to the added section with calculated sizes

		if (info.get_callbacks_rva () != 0) // If TLS has at least one callback
			info.add_tls_callback (0x100); // Add a new callback to TLS - the relative address is most likely incorrect, so the program will not start (just for example)

		info.set_raw_data ("Hello, world!"); // Set or replace the raw TLS data
		info.set_raw_data_start_rva (image.rva_from_section_offset (attached_section, 0)); // Arrange them from the beginning of the added section
		info.recalc_raw_data_end_rva (); // Calculate the new end address of the raw data

		// Rebuild TLS, placing them from the 50th byte (it will be aligned, the section will be automatically expanded) of the new section and writing the new TLS data to the PE header
		// By default, the function also reassembles TLS callbacks and raw TLS data, placing them at the addresses specified in the info structure
		// The expand option allows you to specify how the raw data should be located
		// tls_data_expand_raw allows you to increase the "raw" size of the section, that is, the size in the file
		// tls_data_expand_virtual allows you to increase the virtual size of the section with TLS data
		// If there is not enough space for TLS data, only part of them will be recorded, or nothing will be recorded at all
		rebuild_tls (image, info, attached_section, 50);

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
