#include <iostream>
#include <fstream>
#include "../portable-executable-library2/pe_lib/pe_bliss.h"
//#ifdef PE_BLISS_WINDOWS
#include "../portable-executable-library2/samples/lib.h"
//#endif

using namespace pe_bliss;

// An example showing how to cut out unnecessary data from a PE file and rebuild it
int main (int argc, char * argv [])
{
	if (argc != 2)
	{
		std :: cout << "Usage: pe_stripper.exe PE_FILE" << std :: endl;
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

		// Remove DOS stub and rich overlay
		image.strip_stub_overlay ();

		// Remove Unnecessary DATA_DIRECTORY (null)
		// Very few linkers can do this
		image.strip_data_directories (0);

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

		// Rebuild the PE file with the DOS-header compression option
		// This does not reduce the size, but it packs the NT headers into a DOS header
		// Reassembly automatically removes unnecessary zero bytes at the very end of the image,
		// resulting in a slightly smaller image size
		rebuild_pe (image, new_pe_file, true);

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
