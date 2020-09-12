#include <iostream>
#include <fstream>
#include "../portable-executable-library2/pe_lib/pe_bliss.h"
//#ifdef PE_BLISS_WINDOWS
#include "../portable-executable-library2/samples/lib.h"
//#endif
#include <vector>
// #include<stdlib.h>
#include <cstdlib>  ]

using namespace pe_bliss;

void getPEfileInformation(pe_base image);

// Example showing how to add a section to a PE file and write some data to it
int main(int argc, char *argv[])
{
	if (argc < 4)
	{
		std::cout << "[!] Usage: section_adder.exe PE_FILE SECTION_NAME PE_FILE_CONTENT OUTPUT_FILENAME [NUMBER_OF_SECTIONS]" << std::endl;
		return 0;
	}

	int no_of_sections;
	if (argc == 5)
	{
		no_of_sections = 85; //Setting this to zero will ensure that the file is read completely.
	}
	else
	{
		no_of_sections = atoi(argv[5]);
	}

	std::ifstream sections_file(argv[2]);
	std::ifstream sections_content(argv[3]);
	std::string word, sec_content;
	std::vector<std::string> section_word;

	// std::string section_name = argv[2];
	std::string section_name;
	int section_counter = 0;
	int no_of_words = 0;

	// std::cout << "[*] Starting Section adding procedure ... \n";
	// std::cout << "\t[+] PE File : " << argv[1] << std::endl;
	// std::cout << "\t[+] Section name : " << argv[2] << std::endl;
	// std::cout << "\t[+] Number of Sections : " << no_of_sections << std::endl
		// << std::endl;

	std::string modified_filename = argv[4];

	while (sections_content >> word)
	{
		section_word.push_back(word);
	}




	//Open the file.
	std::ifstream pe_file(argv[1], std::ios::in | std::ios::binary);
	if (!pe_file)
	{
		std::cout << "[!] Cannot open " << argv[1] << std::endl;
		return -1;
	}

	try
	{
		// Create an instance of a PE or PE + class using the factory
		pe_base image(pe_factory::create_pe(pe_file));

		//Get the section information for the file before section addition.
		//getPEfileInformation(image);

		// The section can be added only after all existing so that the PE-file does not deteriorate
		// Create a new section
		section new_section;

		while (std::getline(sections_file, section_name))
		{
			if (section_counter > no_of_sections && no_of_sections)
			{
				std::cout << "Maximum number of Section addition reached!" << std::endl;
				break;
			}

			 no_of_words = int(rand()%100);




			 sec_content = "MS ";


			 //std::cout << "[+] Randomly generated number of Words : " << no_of_words << std::endl;




			 //std::cout << "[+] Randomly generated number of Words : " << no_of_words << std::endl;

			 sec_content = "MS ";


			 for(int index = 0; index < no_of_words; index++)
			 {
			 	sec_content += section_word.at(rand()%section_word.size() - 1) + " ";
			 }




			//std::cout << "[+] Randomly generated section content : " << sec_content << std::endl << std::endl;



			//std::cout << "[+] Randomly generated section content : " << sec_content << std::endl << std::endl;


			new_section.readable(true).writeable(true);		// Make The Section Readable And Writable
			new_section.set_name(section_name);				// Set the section name - maximum 8 characters
			new_section.set_raw_data("Thank you for choosing Microsoft Office 2013. This is a license agreement between you and Microsoft Corporation (or, based on where you live, one of its affiliates) that describes your rights to use the Office 2013 software. For your convenience, we’ve organized this agreement into two parts. The first part includes introductory terms; "); // Set section data

			// Add a section. All addresses are recalculated automatically
			// The call will return a link to an already added section with recalculated addresses
			// You cannot add a completely empty section to the image; it must have a non-zero data size or virtual size
			section &added_section = image.add_section(new_section);

			// If you need to change the virtual size of the section, then this is done like this:
			//image.set_section_virtual_size(added_section, 0x1000);

			section_counter++;
		}

		// Create a new PE file
		std::ofstream new_pe_file(modified_filename.c_str(), std::ios::out | std::ios::binary | std::ios::trunc);
		if (!new_pe_file)
		{
			// std::cout << "[" << section_counter << "] Cannot create " << modified_filename << std::endl;
			return -1;
		}

		//Get the section information for the file before section addition.
		//getPEfileInformation(image);

		// Rebuild the PE file
		rebuild_pe(image, new_pe_file, true, true);



			// << "[*] PE was rebuilt and saved to " << modified_filename << std::endl;


		//std::cout << std::endl
			//<< "[*] PE was rebuilt and saved to " << modified_filename << std::endl;

	}
	catch (const pe_exception &e)
	{
		// If an error occurs
		// std::cout << "[" << section_counter << "] Error: " << e.what() << std::endl;
		return -1;
	}

	return 0;
}

void getPEfileInformation(pe_base image)
{
	// Get the list of sections
	std::cout << "[*] Reading PE sections ..." << std::hex << std::showbase << std::endl;
	const section_list sections(image.get_image_sections());

	// List sections and display information about them
	for (section_list::const_iterator it = sections.begin(); it != sections.end(); ++it)
	{
		const section &s = *it;															//Секция
		std::cout << "\t[+] Section [" << s.get_name() << "]" << std::endl				// Section name
			<< "\t[+] Characteristics:" << s.get_characteristics() << std::endl   // Features
			<< "\t[+] Size of raw data:" << s.get_size_of_raw_data() << std::endl // Data size in file
			<< "\t[+] Virtual address:" << s.get_virtual_address() << std::endl   // Virtual address
			<< "\t[+] Virtual size:" << s.get_virtual_size() << std::endl			// Virtual size
			<< std::endl;
	}
}
